from flask import Flask, request, jsonify
import ldap

app = Flask(__name__)

def ldap_verify(ldap_server, ldap_base_dn, ldap_bind_dn, ldap_password, ldap_group):

    # Extract the user part from ldap_bind_dn
    ldap_bind_dn_parts = ldap_bind_dn.split(',')
    ldap_username_part = next(part for part in ldap_bind_dn_parts if part.startswith("cn="))
    ldap_username = ldap_username_part.split('=')[1]

    # Initialize the LDAP connection
    conn = ldap.initialize(ldap_server)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.simple_bind_s(ldap_bind_dn, ldap_password)

    # Search for the user in the specified group
    search_filter = f"(&(cn={ldap_username})(memberOf=cn={ldap_group},ou=groups,{ldap_base_dn}))"
    result = conn.search_s(ldap_base_dn, ldap.SCOPE_SUBTREE, search_filter)

    return result

@app.route('/verify', methods=['POST'])
def authenticate():
    data = request.json
    ldap_server = data.get('ldap_server')
    ldap_base_dn = data.get('ldap_base_dn')
    ldap_bind_dn = data.get('ldap_bind_dn')
    ldap_password = data.get('ldap_password')
    ldap_group = data.get('ldap_group')

    result = ldap_verify(ldap_server, ldap_base_dn, ldap_bind_dn, ldap_password, ldap_group)
    return jsonify(result)
