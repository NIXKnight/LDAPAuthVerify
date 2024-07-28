from flask import Flask, request, jsonify
import ldap
from os import getenv
import re

app = Flask(__name__)

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
        conn = ldap.initialize(ldap_server)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.simple_bind_s(ldap_bind_dn, ldap_password)

        # Get the actual username if ldap_username is an email address
        if is_ldap_username_email(ldap_username):
            actual_username = get_username_for_email(ldap_base_dn, ldap_username, conn)
        else:
            actual_username = ldap_username

        # Get LDAP group search result
        result = search_user_in_group(ldap_base_dn, actual_username, ldap_group, conn)

        if result:
            log = f"User {ldap_username} authenticated successfully and found in group {ldap_group}."
            return {"success": True, "log": log}
        else:
            log = f"User {ldap_username} authenticated successfully but not found in group {ldap_group}."
            return {"success": False, "log": log}

    except ldap.INVALID_CREDENTIALS:
        log = "Invalid credentials"
        return {"success": False, "log": log}

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    ldap_base_dn = data.get('ldap_base_dn')
    ldap_username = data.get('ldap_username')
    ldap_password = data.get('ldap_password')
    ldap_group = data.get('ldap_group')

    result = ldap_verify(ldap_base_dn, ldap_username, ldap_password, ldap_group)
    return jsonify(result)
