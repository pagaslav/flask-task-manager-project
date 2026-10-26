"""Exercise Flask routes with an isolated in-memory database; no network."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import mongomock
from bson import ObjectId
from werkzeug.security import generate_password_hash


class TaskAccessTests(unittest.TestCase):
    def setUp(self):
        self.db = mongomock.MongoClient().task_test
        spec = importlib.util.spec_from_file_location('task_app', Path(__file__).resolve().parents[1] / 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        self.env = patch.dict(os.environ, {'SECRET_KEY': 'test-only', 'TASK_ADMIN_USERNAME': 'admin'}, clear=True)
        self.env.start()
        with patch('flask_pymongo.PyMongo', return_value=SimpleNamespace(db=self.db)):
            spec.loader.exec_module(self.module)
        self.module.app.config.update(TESTING=True)
        self.client = self.module.app.test_client()
        self.addCleanup(self.env.stop)
        self.task_id = self.db.tasks.insert_one({'created_by': 'alice', 'task_name': 'Alice private task'}).inserted_id
        self.category_id = self.db.categories.insert_one({'category_name': 'A'}).inserted_id

    def login_as(self, username):
        with self.client.session_transaction() as session:
            session.clear()
            session['_csrf_token'] = 'test-token'
            if username:
                session['user'] = username

    def post(self, path, data=None):
        return self.client.post(path, data=data or {}, headers={'X-CSRF-Token': 'test-token'})

    def test_get_never_deletes(self):
        self.login_as('alice')
        self.assertEqual(self.client.get(f'/delete_task/{self.task_id}').status_code, 405)
        self.assertEqual(self.client.get(f'/delete_category/{self.category_id}').status_code, 405)
        self.assertEqual(self.db.tasks.count_documents({}), 1)

    def test_guest_and_other_user_cannot_delete(self):
        for user, status in [(None, 403), ('bob', 404)]:
            self.login_as(user)
            self.assertEqual(self.post(f'/delete_task/{self.task_id}').status_code, status)
            self.assertEqual(self.db.tasks.count_documents({}), 1)

    def test_owner_can_delete_with_csrf(self):
        self.login_as('alice')
        self.assertEqual(self.post(f'/delete_task/{self.task_id}').status_code, 302)
        self.assertEqual(self.db.tasks.count_documents({}), 0)

    def test_csrf_is_required_even_for_owner(self):
        self.login_as('alice')
        self.assertEqual(self.client.post(f'/delete_task/{self.task_id}').status_code, 403)
        self.assertEqual(self.db.tasks.count_documents({}), 1)

    def test_foreign_edit_cannot_change_owner_or_content(self):
        self.login_as('bob')
        for method in ('get', 'post'):
            response = self.client.get(f'/edit_task/{self.task_id}') if method == 'get' else self.post(f'/edit_task/{self.task_id}', {'task_name': 'Changed'})
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.db.tasks.find_one({'_id': self.task_id})['task_name'], 'Alice private task')

    def test_category_admin_and_fail_closed_configuration(self):
        for user, status in [(None, 403), ('alice', 403), ('admin', 302)]:
            self.login_as(user)
            self.assertEqual(self.post(f'/delete_category/{self.category_id}').status_code, status)
        os.environ.pop('TASK_ADMIN_USERNAME')
        self.assertEqual(self.post(f'/delete_category/{self.category_id}').status_code, 403)

    def test_registration_cannot_impersonate_trimmed_username(self):
        self.db.users.insert_one({'username': 'alice', 'password': generate_password_hash('AlicePassword1')})
        self.login_as(None)
        self.post('/register', {'username': ' alice ', 'password': 'AttackerPassword1'})
        with self.client.session_transaction() as session:
            self.assertNotIn('user', session)
        self.assertEqual(self.db.users.count_documents({}), 1)

    def test_new_registration_uses_same_stored_and_session_identity(self):
        self.login_as(None)
        self.post('/register', {'username': ' NewUser ', 'password': 'TestPassword1'})
        self.assertIsNotNone(self.db.users.find_one({'username': 'newuser'}))
        with self.client.session_transaction() as session:
            self.assertEqual(session['user'], 'newuser')

    def test_legacy_whitespace_account_login_does_not_adopt_other_identity(self):
        self.db.users.insert_one({'username': ' alice ', 'password': generate_password_hash('TestPassword1')})
        self.login_as(None)
        self.post('/login', {'username': ' alice ', 'password': 'TestPassword1'})
        with self.client.session_transaction() as session:
            self.assertEqual(session['user'], ' alice ')
        self.assertEqual(self.post(f'/delete_task/{self.task_id}').status_code, 403)

    def test_reserved_admin_registration_and_bad_ids(self):
        self.login_as(None)
        self.assertEqual(self.post('/register', {'username': ' Admin ', 'password': 'TestPassword1'}).status_code, 403)
        self.login_as('alice')
        self.assertEqual(self.post('/delete_task/invalid').status_code, 404)

    def test_real_login_route_enforces_shared_budget_before_password_check(self):
        self.db.users.insert_one({'username':'alice','password':'synthetic hash'})
        self.login_as(None)
        with patch.object(self.module, 'check_password_hash', return_value=False) as verify:
            for _ in range(10):
                self.assertEqual(self.post('/login', {'username':'alice','password':'wrong'}).status_code, 302)
            self.assertEqual(self.post('/login', {'username':'alice','password':'wrong'}).status_code, 429)
            self.assertEqual(verify.call_count, 10)

    def test_concurrent_registration_cannot_claim_existing_task_identity(self):
        self.login_as(None)
        original = self.db.users.insert_one
        def concurrent_signup(document):
            victim = dict(document, password=generate_password_hash('VictimPassword1'))
            original(victim)
            return original(document)
        with patch.object(self.db.users, 'insert_one', side_effect=concurrent_signup):
            response = self.post('/register', {'username':' Alice ', 'password':'AttackerPassword1'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.db.users.count_documents({'username':'alice'}), 1)
        with self.client.session_transaction() as session:
            self.assertNotIn('user', session)
        self.assertEqual(self.db.tasks.find_one({'_id':self.task_id})['created_by'], 'alice')


if __name__ == '__main__':
    unittest.main()
