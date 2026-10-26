"""Synthetic request budgets and opt-in isolated MongoDB concurrency checks."""
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor
import uuid

from flask import Flask
import mongomock
from pymongo import MongoClient
from pymongo.errors import AutoReconnect, DuplicateKeyError
import security_login


def harness(db):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY='synthetic-only')
    work = Mock()
    @app.post('/login')
    def login():
        from flask import request
        security_login.enforce_login_limits(app, SimpleNamespace(db=db), request.form.get('account', ''))
        work()
        return '', 204
    return app, work


class LoginBudgetTests(TestCase):
    def setUp(self):
        self.db = mongomock.MongoClient().login_test
        self.app, self.work = harness(self.db)
        self.clock = SimpleNamespace(time=lambda: 1800000000)
        patcher = patch.object(security_login, 'time', self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def attempt(self, account='patient@example.invalid', ip='192.0.2.1', headers=None):
        # A new cookie jar on every attempt must not reset the shared budget.
        return self.app.test_client().post('/login', data={'account':account}, environ_overrides={'REMOTE_ADDR':ip}, headers=headers or {})

    def test_account_limit_survives_new_clients_and_ip_changes(self):
        for index in range(10):
            self.assertEqual(self.attempt(ip=f'192.0.2.{index+1}').status_code, 204)
        blocked = self.attempt(ip='198.51.100.1')
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers['Retry-After'], '900')
        self.assertEqual(self.work.call_count, 10)

    def test_ip_budget_ignores_forged_forwarding_headers(self):
        for index in range(100):
            self.assertEqual(self.attempt(account=f'account{index}', headers={'X-Forwarded-For':f'198.51.100.{index+1}'}).status_code, 204)
        self.assertEqual(self.attempt(account='another', headers={'X-Forwarded-For':'203.0.113.2'}).status_code, 429)
        self.assertEqual(self.work.call_count, 100)
        self.assertEqual(self.db.security_login_limits.count_documents({'_id': {'$regex':'^account:'}}), 100)

    def test_case_and_whitespace_share_an_account_budget(self):
        for index in range(10):
            self.assertEqual(self.attempt(account='  Patient@EXAMPLE.invalid  ' if index%2 else 'patient@example.invalid').status_code, 204)
        self.assertEqual(self.attempt(account='PATIENT@example.invalid').status_code, 429)

    def test_window_recovers_and_only_expired_counter_rows_are_removed(self):
        self.db.users.insert_one({'name':'synthetic patient'})
        for _ in range(10):
            self.attempt()
        self.assertEqual(self.attempt().status_code, 429)
        self.clock.time = lambda:1800000901
        self.assertEqual(self.attempt().status_code, 204)
        self.assertEqual(self.db.security_login_limits.count_documents({}), 2)
        self.assertEqual(self.db.users.count_documents({}), 1)

    def test_new_process_uses_existing_database_budget(self):
        for _ in range(10):
            self.attempt()
        new_app, work = harness(self.db)
        self.assertEqual(new_app.test_client().post('/login', data={'account':'patient@example.invalid'}).status_code, 429)
        work.assert_not_called()

    def test_storage_failure_fails_closed_without_work_or_details(self):
        with patch.object(self.db.security_login_limits, 'find_one_and_update', side_effect=AutoReconnect('private database connection string')):
            result = self.attempt()
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(b'private database connection', result.data)
        self.work.assert_not_called()

    def test_concurrent_first_insert_is_retried_without_resetting_count(self):
        collection = self.db.security_login_limits
        original = collection.find_one_and_update
        raced = False
        def race(selector, update, **options):
            nonlocal raced
            if not raced:
                raced = True
                original(selector, update, **options)
                raise DuplicateKeyError('synthetic competing insert')
            return original(selector, update, **options)
        with patch.object(collection, 'find_one_and_update', side_effect=race):
            self.assertEqual(self.attempt().status_code, 204)
        ip = collection.find_one({'_id': {'$regex':'^ip:'}})
        self.assertEqual(ip['attempts'], 2)

    def test_counters_do_not_store_plaintext_identifiers_or_credentials(self):
        self.attempt()
        encoded = json.dumps(list(self.db.security_login_limits.find()), default=str)
        for value in ('patient@example.invalid','192.0.2.1','synthetic-only'):
            self.assertNotIn(value, encoded)
        for document in self.db.security_login_limits.find():
            self.assertEqual(set(document), {'_id','attempts','expires_at'})


@skipUnless(os.environ.get('SECURITY_TEST_MONGO_URI'), 'CI-only disposable MongoDB service is not configured')
class MongoConcurrencyTests(TestCase):
    def setUp(self):
        self.mongo = MongoClient(os.environ['SECURITY_TEST_MONGO_URI'], serverSelectionTimeoutMS=5000)
        self.db_name = 'security_test_login_' + uuid.uuid4().hex
        self.db = self.mongo[self.db_name]
        self.app, self.work = harness(self.db)
        patcher = patch.object(security_login, 'time', SimpleNamespace(time=lambda:1800000000))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.mongo.close)
        self.addCleanup(lambda:self.mongo.drop_database(self.db_name) if self.db_name.startswith('security_test_login_') else None)

    def test_atomic_account_budget_across_concurrent_requests(self):
        def attempt(index):
            with self.app.test_client() as client:
                return client.post('/login', data={'account':'patient@example.invalid'}, environ_overrides={'REMOTE_ADDR':f'192.0.2.{index+1}'}).status_code
        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(attempt, range(40)))
        self.assertEqual(statuses.count(204), 10)
        self.assertEqual(statuses.count(429), 30)
        account = self.db.security_login_limits.find_one({'_id':{'$regex':'^account:'}})
        self.assertEqual(account['attempts'], 40)

    def test_atomic_ip_budget_across_concurrent_accounts(self):
        def attempt(index):
            with self.app.test_client() as client:
                return client.post('/login', data={'account':f'account-{index}'}, environ_overrides={'REMOTE_ADDR':'192.0.2.1'}).status_code
        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(attempt, range(120)))
        self.assertEqual(statuses.count(204), 100)
        self.assertEqual(statuses.count(429), 20)
        self.assertEqual(self.db.security_login_limits.find_one({'_id':{'$regex':'^ip:'}})['attempts'], 120)
        self.assertEqual(self.db.security_login_limits.count_documents({'_id':{'$regex':'^account:'}}), 100)
