"""Shared MongoDB login budgets; independent of process memory and cookies."""
from datetime import datetime, timezone
import hashlib
import hmac
import time

from flask import request, abort
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.exceptions import TooManyRequests


def enforce_login_limits(app, mongo, account):
    window = 900
    epoch = int(time.time())
    bucket = epoch // window
    expires = datetime.fromtimestamp((bucket + 1) * window, timezone.utc)
    secret = app.secret_key
    if not secret:
        abort(503)
    key = secret.encode() if isinstance(secret, str) else secret
    limits = mongo.db.security_login_limits
    # Socket peer only. Forwarded headers are not trusted by this application.
    budgets = [('ip', request.remote_addr or 'unknown', 100),
               ('account', account.strip().lower(), 10)]
    try:
        limits.delete_many({'expires_at': {'$lte': datetime.fromtimestamp(epoch, timezone.utc)}})
        for kind, value, maximum in budgets:
            digest = hmac.new(key, (kind + ':' + value).encode(), hashlib.sha256).hexdigest()
            selector = {'_id': f'{kind}:{digest}:{bucket}'}
            update = {'$inc': {'attempts': 1}, '$setOnInsert': {'expires_at': expires}}
            try:
                document = limits.find_one_and_update(selector, update, upsert=True, return_document=ReturnDocument.AFTER)
            except DuplicateKeyError:
                # A concurrent first upsert may have inserted the same _id.
                document = limits.find_one_and_update(selector, {'$inc': {'attempts': 1}}, return_document=ReturnDocument.AFTER)
            if not document:
                abort(503)
            if document['attempts'] > maximum:
                response = TooManyRequests(description='Too many sign-in attempts. Try again later.', retry_after=window - epoch % window).get_response()
                response.headers['Cache-Control'] = 'no-store'
                abort(response)
    except PyMongoError:
        # Never silently disable the distributed limit when storage fails.
        abort(503, description='Sign-in is temporarily unavailable.')
