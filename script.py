#!/usr/bin/env python3

import requests
import time
import schedule
import hashlib
import hmac
import binascii
import base64
import json
import re
from urllib.parse import parse_qs, urlencode, urlparse

__version__ = "3.1.0"

FACEBOOK_GRAPH_URL = "https://graph.facebook.com/"
FACEBOOK_WWW_URL = "https://www.facebook.com/"
FACEBOOK_OAUTH_DIALOG_PATH = "dialog/oauth?"
VALID_API_VERSIONS = ["2.8", "2.9", "2.10", "2.11", "2.12", "3.0", "3.1"]
VALID_SEARCH_TYPES = ["place", "placetopic"]

class GraphAPI(object):
    def __init__(self, access_token=None, timeout=None, version=None, proxies=None, session=None):
        default_version = VALID_API_VERSIONS[0]

        self.access_token = access_token
        self.timeout = timeout
        self.proxies = proxies
        self.session = session or requests.Session()

        if version:
            version_regex = re.compile("^\d\.\d{1,2}$")
            match = version_regex.search(str(version))
            if match is not None:
                if str(version) not in VALID_API_VERSIONS:
                    raise GraphAPIError(
                        "Valid API versions are "
                        + str(VALID_API_VERSIONS).strip("[]")
                    )
                else:
                    self.version = "v" + str(version)
            else:
                raise GraphAPIError(
                    "Version number should be in the"
                    " following format: #.# (e.g. 2.0)."
                )
        else:
            self.version = "v" + default_version

    def get_permissions(self, user_id):
        response = self.requests("{0}/{1}/permissions".format(self.version, user_id), {})["data"]
        return {x["permission"] for x in response if x["status"] == "granted"}

    def get_objects(self, id, **args):
        return self.request("{0}/{1}".format(self.version, id), args)

    def get_objects(self, ids, **args):
        args["ids"] = ",".join(ids)
        return self.request(self.version + "/", args)

    def search(self, type, **args):
        if type not in VALID_SEARCH_TYPES:
            raise GraphAPIError("Valid types are: %s" % ", ".join(VALID_SEARCH_TYPES))

        args["type"] = type
        return self.request(self.version + "/search/", args)

    def get_connections(self, id, connection_name, **args):
        return self.request( "{0}/{1}/{2}".format(self.version, id, connection_name), args)

    def get_all_connections(self, id, connection_name, **args):
        while True:
            page = self.get_connections(id, connection_name, **args)
            for post in page["data"]:
                yield post
            next = page.get("paging", {}).get("next")
            if not next:
                return
            args = parse_qs(urlparse(next).query)
            del args["access_token"]

    def put_object(self, parent_object, connection_name, **data):
        assert self.access_token, "Write operations require an access token"
        return self.request("{0}/{1}/{2}".format(self.version, parent_object, connection_name),
            post_args=data, method="POST")

    def put_comment(self, object_id, message):
        return self.put_object(object_id, "comments", message=message)

    def put_like(self, object_id):
        return self.put_object(object_id, "likes")

    def delete_object(self, id):
        return self.request("{0}/{1}".format(self.version, id), method="DELETE")

    def delete_request(self, user_id, request_id):
        return self.request("{0}_{1}".format(request_id, user_id), method="DELETE" )

    def put_photo(self, image, album_path="me/photos", **kwargs):
        return self.request("{0}/{1}".format(self.version, album_path), post_args=kwargs, files={"source": image}, method="POST")

    def get_version(self):
        args = {"access_token": self.access_token}
        try:
            response = self.session.request(
                "GET",
                FACEBOOK_GRAPH_URL + self.version + "/me",
                params=args,
                timeout=self.timeout,
                proxies=self.proxies,
            )
        except requests.HTTPError as e:
            response = json.loads(e.read())
            raise GraphAPIError(response)

        try:
            headers = response.headers
            version = headers["facebook-api-version"].replace("v", "")
            return str(version)
        except Exception:
            raise GraphAPIError("API version number not available")

    def request(self, path, args=None, post_args=None, files=None, method=None):
        if args is None:
            args = dict()
        if post_args is not None:
            method = "POST"
        if self.access_token:
            if post_args and "access_token" not in post_args:
                post_args["access_token"] = self.access_token
            elif "access_token" not in args:
                args["access_token"] = self.access_token

        try:
            response = self.session.request(
                method or "GET",
                FACEBOOK_GRAPH_URL + path,
                timeout=self.timeout,
                params=args,
                data=post_args,
                proxies=self.proxies,
                files=files,
            )
        except requests.HTTPError as e:
            response = json.loads(e.read())
            raise GraphAPIError(response)

        headers = response.headers
        if "json" in headers["content-type"]:
            result = response.json()
        elif "image/" in headers["content-type"]:
            mimetype = headers["content-type"]
            result = {
                "data": response.content,
                "mime-type": mimetype,
                "url": response.url,
            }
        elif "access_token" in parse_qs(response.text):
            query_str = parse_qs(response.text)
            if "access_token" in query_str:
                result = {"access_token": query_str["access_token"][0]}
                if "expires" in query_str:
                    result["expires"] = query_str["expires"][0]
            else:
                raise GraphAPIError(response.json())
        else:
            raise GraphAPIError("Maintype was not text, image, or querystring")

        if result and isinstance(result, dict) and result.get("error"):
            raise GraphAPIError(result)
        return result

    def get_app_access_token(self, app_id, app_secret, offline=False):
        if offline:
            return "{0}|{1}".format(app_id, app_secret)
        else:
            args = {
                "grant_type": "client_credentials",
                "client_id": app_id,
                "client_secret": app_secret,
            }

            return self.request("{0}/oauth/access_token".format(self.version), args=args)["access_token"]

    def get_access_token_from_code(self, code, redirect_uri, app_id, app_secret):
        args = {
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": app_id,
            "client_secret": app_secret,
        }

        return self.request("{0}/oauth/access_token".format(self.version), args)

    def extend_access_token(self, app_id, app_secret):
        args = {
            "client_id": app_id,
            "client_secret": app_secret,
            "grant_type": "fb_exchange_token",
            "fb_exchange_token": self.access_token,
        }

        return self.request("{0}/oauth/access_token".format(self.version), args=args)

    def debug_access_token(self, token, app_id, app_secret):
        args = {
            "input_token": token,
            "access_token": "{0}|{1}".format(app_id, app_secret),
        }
        return self.request(self.version + "/" + "debug_token", args=args)

    def get_auth_url(self, app_id, canvas_url, perms=None, **kwargs):
        url = "{0}{1}/{2}".format(
            FACEBOOK_WWW_URL, self.version, FACEBOOK_OAUTH_DIALOG_PATH
        )

        args = {"client_id": app_id, "redirect_uri": canvas_url}
        if perms:
            args["scope"] = ",".join(perms)
        args.update(kwargs)
        return url + urlencode(args)

class GraphAPIError(Exception):
    def __init__(self, result):
        self.result = result
        self.code = None
        try:
            self.type = result["error_code"]
        except (KeyError, TypeError):
            self.type = ""

        # OAuth 2.0 Draft 10
        try:
            self.message = result["error_description"]
        except (KeyError, TypeError):
            # OAuth 2.0 Draft 00
            try:
                self.message = result["error"]["message"]
                self.code = result["error"].get("code")
                if not self.type:
                    self.type = result["error"].get("type", "")
            except (KeyError, TypeError):
                # REST server style
                try:
                    self.message = result["error_msg"]
                except (KeyError, TypeError):
                    self.message = result

        Exception.__init__(self, self.message)

def get_user_from_cookie(cookies, app_id, app_secret):
    cookie = cookies.get("fbsr_" + app_id, "")
    if not cookie:
        return None
    parsed_request = parse_signed_request(cookie, app_secret)
    if not parsed_request:
        return None
    try:
        result = GraphAPI().get_access_token_from_code(
            parsed_request["code"], "", app_id, app_secret
        )
    except GraphAPIError:
        return None
    result["uid"] = parsed_request["user_id"]
    return result

def parse_signed_request(signed_request, app_secret):
    try:
        encoded_sig, payload = map(str, signed_request.split(".", 1))

        sig = base64.urlsafe_b64decode(
            encoded_sig + "=" * ((4 - len(encoded_sig) % 4) % 4)
        )
        data = base64.urlsafe_b64decode(
            payload + "=" * ((4 - len(payload) % 4) % 4)
        )
    except IndexError:
        # Signed request was malformed.
        return False
    except TypeError:
        # Signed request had a corrupted payload.
        return False
    except binascii.Error:
        # Signed request had a corrupted payload.
        return False

    data = json.loads(data.decode("ascii"))
    if data.get("algorithm", "").upper() != "HMAC-SHA256":
        return False

    # HMAC can only handle ascii (byte) strings
    # https://bugs.python.org/issue5285
    app_secret = app_secret.encode("ascii")
    payload = payload.encode("ascii")

    expected_sig = hmac.new(
        app_secret, msg=payload, digestmod=hashlib.sha256
    ).digest()
    if sig != expected_sig:
        return False

    return data

from stuff import *

def post_on_facebook():
    fb_access_token = key

    with open('last_posted_frame.txt') as file:

        """last_posted_frame.txt file keeps track of the framw which
        was posted last in case the script stops running for some
        reason, reducing further annoyance."""

        last_frame = int(file.readline())
        
    to_post = last_frame + 1
    filename = "extract-frames/" + str(to_post) + ".jpg"

    text = f"Frame {to_post} of {total_frames}"

    with open(filename, 'rb') as image:
        GraphAPI(access_token = fb_access_token).put_photo(image = image, message = text)

    with open('last_posted_frame.txt') as file:
        file.write(str(to_post))


if __name__ == "__main__":

    """Scheduling the script to post every 5 minutes.
        change as required."""
    schedule.every(5).minutes.do(post_on_facebook).run()

    while True:
        schedule.run_pending()
        time.sleep(1)
