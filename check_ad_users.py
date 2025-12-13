"""
Script to check if users from a CSV file exist and are active in Active Directory.
Requires: pip install ldap3
"""

import csv
from ldap3 import Server, Connection, ALL, NTLM
from typing import List, Dict

# Active Directory Configuration
AD_SERVER = 'your-ad-server.domain.com'  # Replace with your AD server
AD_DOMAIN = 'DOMAIN'  # Replace with your domain name
AD_USER = 'DOMAIN\\username'  # Replace with your AD username
AD_PASSWORD = 'password'  # Replace with your password or use getpass
AD_SEARCH_BASE = 'DC=domain,DC=com'  # Replace with your search base

def connect_to_ad(server: str, user: str, password: str) -> Connection:
    """
    Establish connection to Active Directory.

    Args:
        server: AD server address
        user: Username for authentication
        password: Password for authentication

    Returns:
        Connection object
    """
    try:
        ad_server = Server(server, get_info=ALL)
        conn = Connection(ad_server, user=user, password=password, authentication=NTLM, auto_bind=True)
        print(f"Successfully connected to {server}")
        return conn
    except Exception as e:
        print(f"Failed to connect to AD: {e}")
        raise

def check_user_in_ad(conn: Connection, username: str, search_base: str) -> Dict:
    """
    Check if a user exists and is active in Active Directory.

    Args:
        conn: LDAP connection object
        username: Username to search for
        search_base: LDAP search base

    Returns:
        Dictionary with user status information
    """
    search_filter = f'(sAMAccountName={username})'
    attributes = ['sAMAccountName', 'userAccountControl', 'displayName', 'mail', 'whenCreated']

    try:
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes
        )

        if len(conn.entries) == 0:
            return {
                'username': username,
                'exists': False,
                'is_active': False,
                'display_name': '',
                'email': '',
                'status': 'User not found'
            }

        entry = conn.entries[0]

        # Check if account is enabled (userAccountControl)
        # If bit 2 (0x0002) is set, account is disabled
        user_account_control = int(entry.userAccountControl.value)
        is_disabled = bool(user_account_control & 2)
        is_active = not is_disabled

        return {
            'username': username,
            'exists': True,
            'is_active': is_active,
            'display_name': str(entry.displayName.value) if entry.displayName else '',
            'email': str(entry.mail.value) if entry.mail else '',
            'status': 'Active' if is_active else 'Disabled'
        }

    except Exception as e:
        return {
            'username': username,
            'exists': False,
            'is_active': False,
            'display_name': '',
            'email': '',
            'status': f'Error: {str(e)}'
        }

def read_usernames_from_csv(csv_file: str, username_column: str = 'username') -> List[str]:
    """
    Read usernames from a CSV file.

    Args:
        csv_file: Path to the CSV file
        username_column: Name of the column containing usernames

    Returns:
        List of usernames
    """
    usernames = []
    try:
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if username_column in row:
                    username = row[username_column].strip()
                    if username:  # Skip empty usernames
                        usernames.append(username)
        print(f"Read {len(usernames)} usernames from {csv_file}")
        return usernames
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        raise

def write_results_to_csv(results: List[Dict], output_file: str):
    """
    Write results to a CSV file.

    Args:
        results: List of result dictionaries
        output_file: Path to the output CSV file
    """
    if not results:
        print("No results to write")
        return

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as file:
            fieldnames = ['username', 'exists', 'is_active', 'display_name', 'email', 'status']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"Results written to {output_file}")
    except Exception as e:
        print(f"Error writing results: {e}")
        raise

def main():
    """Main function to check AD users."""
    # Configuration
    INPUT_CSV = 'usernames.csv'  # Replace with your input CSV file
    OUTPUT_CSV = 'ad_check_results.csv'
    USERNAME_COLUMN = 'username'  # Column name in CSV containing usernames

    print("=" * 60)
    print("Active Directory User Check Script")
    print("=" * 60)

    # Read usernames from CSV
    print("\nStep 1: Reading usernames from CSV...")
    usernames = read_usernames_from_csv(INPUT_CSV, USERNAME_COLUMN)

    # Connect to Active Directory
    print("\nStep 2: Connecting to Active Directory...")
    conn = connect_to_ad(AD_SERVER, AD_USER, AD_PASSWORD)

    # Check each user
    print(f"\nStep 3: Checking {len(usernames)} users in Active Directory...")
    results = []

    for i, username in enumerate(usernames, 1):
        print(f"Checking {i}/{len(usernames)}: {username}...", end=' ')
        result = check_user_in_ad(conn, username, AD_SEARCH_BASE)
        results.append(result)
        print(result['status'])

    # Close connection
    conn.unbind()

    # Write results to CSV
    print("\nStep 4: Writing results to CSV...")
    write_results_to_csv(results, OUTPUT_CSV)

    # Print summary
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    total = len(results)
    exists = sum(1 for r in results if r['exists'])
    active = sum(1 for r in results if r['is_active'])
    not_found = total - exists
    disabled = exists - active

    print(f"Total users checked: {total}")
    print(f"Users found in AD: {exists}")
    print(f"Active users: {active}")
    print(f"Disabled users: {disabled}")
    print(f"Users not found: {not_found}")
    print("=" * 60)

if __name__ == '__main__':
    main()
