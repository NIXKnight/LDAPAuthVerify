from flask import Flask, request, jsonify, make_response
import ldap
import logging
from os import getenv
import re

app = Flask(__name__)
app.config['DEBUG'] = getenv('DEBUG', False)

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S %z',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

ldap_server = getenv('LDAP_SERVER', 'ldap://localhost:389')

def is_ldap_username_email(ldap_username):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if re.fullmatch(regex, ldap_username):
        return True
    else:
        return False

def get_username_for_email(ldap_base_dn, email, conn):
    search_filter = f"(mail={email})"
    result = conn.search_s(ldap_base_dn, ldap.SCOPE_SUBTREE, search_filter, ['cn'])
    if result:
        # Extract the cn from the result
        cn = result[0][1]['cn'][0].decode('utf-8')
        return cn
    return None

def group_exists(ldap_base_dn, ldap_group, conn):
    search_filter = f"(cn={ldap_group})"
    result = conn.search_s(f"ou=groups,{ldap_base_dn}", ldap.SCOPE_SUBTREE, search_filter, ['cn'])
    if result:
        return True
    else:
        return False

def search_user_in_group(ldap_base_dn, ldap_username, ldap_group, conn):
    # LDAP group DN for Authentik LDAP search
    ldap_group_dn = f"cn={ldap_group},ou=groups,{ldap_base_dn}"

    search_filter = f"(&(cn={ldap_username})(memberOf={ldap_group_dn}))"
    result = conn.search_s(ldap_base_dn, ldap.SCOPE_SUBTREE, search_filter)
    return result

def ldap_verify(ldap_base_dn, ldap_username, ldap_password, ldap_group):

    # LDAP Bind DN for Authentik login
    ldap_bind_dn = f"cn={ldap_username},ou=users,{ldap_base_dn}"

    try:
        # Initialize the LDAP connection
        logger.info(f"Initializing LDAP connection to {ldap_server} for user {ldap_username}")
        conn = ldap.initialize(ldap_server)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.simple_bind_s(ldap_bind_dn, ldap_password)
        logger.info(f"Successfully autehnticated to LDAP server as {ldap_username}")

        # Verify if the group exists
        if not group_exists(ldap_base_dn, ldap_group, conn):
            log = f"User {ldap_username} authenticated successfully and group {ldap_group} does not exist"
            logger.warn(log)
            return {"success": False, "log": log}, 404

        # Get the actual username if ldap_username is an email address
        if is_ldap_username_email(ldap_username):
            actual_username = get_username_for_email(ldap_base_dn, ldap_username, conn)
        else:
            actual_username = ldap_username

        # Get LDAP group search result
        result = search_user_in_group(ldap_base_dn, actual_username, ldap_group, conn)

        if result:
            log = f"User {ldap_username} authenticated successfully and found in group {ldap_group}"
            logger.info(log)
            return {"success": True, "log": log}, 200
        else:
            log = f"User {ldap_username} authenticated successfully but not found in group {ldap_group}"
            logger.warn(log)
            return {"success": False, "log": log}, 403

    except ldap.INVALID_CREDENTIALS:
        log = f"Invalid credentials - user {ldap_username}"
        logger.error(log)
        return {"success": False, "log": log}, 401

    except ldap.SERVER_DOWN:
        log = f"LDAP connection to LDAP server {ldap_server} for user {ldap_username} failed - LDAP server is down"
        logger.error(log)
        return {"success": False, "log": log}, 503

    finally:
        if conn:
            conn.unbind_s()
            logger.info(f"Closed LDAP connection to {ldap_server} for user {ldap_username}")

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    ldap_base_dn = data.get('ldap_base_dn')
    ldap_username = data.get('ldap_username')
    ldap_password = data.get('ldap_password')
    ldap_group = data.get('ldap_group')

    result, response_code = ldap_verify(ldap_base_dn, ldap_username, ldap_password, ldap_group)
    return make_response(jsonify(result), response_code)
