import requests
import json
import logging
import six

from ckan.plugins import toolkit as tk
from ckan.lib.api_token import decode, encode

log = logging.getLogger(__name__)

base_url = tk.config.get("ckanext.cilogin.base_url")
username = tk.config.get("ckanext.cilogin.username")
password = tk.config.get("ckanext.cilogin.password")
coid = tk.config.get("ckanext.cilogin.coid")
password_authenticator = tk.config.get("ckanext.cilogin.password_authenticator", "5")


ci_login_dict = {
  "RequestType":"Passwords",
  "Version":"1.0",
  "Passwords":
  [
    {
      "Version":"1.0",
      "PasswordAuthenticatorId": None,
      "Person":
      {
        "Type":"CO",
        "Id": None
      },
      "Password": None,
      "PasswordType":"EX"
    }
  ]
}


def process_token(user, token):
    # get the user from clilogon
    base_url = tk.config.get("ckanext.cilogin.base_url")
    cilogin_user = _get_user(base_url, user)
    if not cilogin_user:
        log.error("Could not get user from cilogin")
        return
    cilogin_user_id = cilogin_user.get("CoPeople")[0].get("Id")
    # get the token from cilogin
    cilogin_token_dict = _get_token(base_url, cilogin_user_id, token)
    if not cilogin_token_dict:
        log.error("Could not get token from cilogin")
        return
    # check if the token matches
    cilogin_token = cilogin_token_dict.get("Passwords")[0].get("Password")
    if not _compare_tokens(cilogin_token, token):
        log.error("Token does not match")
        _update_or_create_token(base_url, cilogin_user_id, cilogin_token_dict, token)
        return


def _get_user(base_url,user):
    user_url = f"{base_url}/co_people.json"
    email = user.get("email", None)
    if not email:
        log.info("No email found for user %s", user.get("name"))

    params = {"coid": coid, "mail": email }
    try:
        response = requests.get(url=user_url, auth=(username, password), params=params)
    except Exception as e:
        log.error("Could not get user from cilogin")
        log.error(e)
    if response.status_code == 200:
        return json.loads(response.text)
    else:
        log.error(response.reason)


def _get_token(base_url, cilogin_user_id, token):
    token_url = f"{base_url}/password_authenticator/passwords.json"
    params = {"coid": coid, "copersonid": cilogin_user_id }
    try:
        response = requests.get(url=token_url, auth=(username, password), params=params)
    except Exception as e:
        log.error("Could not get token from cilogin")
        log.error(e)
    if response.status_code == 200:
        return json.loads(response.text)
    elif response.status_code == 204:
        log.info("No token found for user %s. We should add one", cilogin_user_id)
        return _update_or_create_token(
            base_url, cilogin_user_id, ci_login_dict, token
        )
    else:
        log.error(response.reason)


def _update_or_create_token(base_url, cilogin_user_id, cilogin_token_dict, token):
    response = None
    token = six.ensure_str(encode(token)) if isinstance(token, dict) else six.ensure_str(token)
    token_url = f"{base_url}/password_authenticator/passwords.json"
    cilogin_token_dict.get("Passwords")[0]["Password"] = token
    cilogin_token_dict.get("Passwords")[0]["Person"]["Id"] = cilogin_user_id
    cilogin_token_dict.get("Passwords")[0]["PasswordAuthenticatorId"] = password_authenticator
    data = json.dumps(cilogin_token_dict)
    try:
        response = requests.post(url=token_url, auth=(username, password), data=data)
    except Exception as e:
        log.error("Could not update token from cilogin")
        log.error(e)
    if response.status_code == 200:
        return json.loads(response.text)
    else:
        log.error(response.reason)


def _compare_tokens(cilogin_token, token):
    jti = None
    if isinstance(token, dict):
        jti = encode(token)
    return cilogin_token == token or cilogin_token == jti