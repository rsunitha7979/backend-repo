import json
import boto3
import os
import psycopg2
from botocore.exceptions import ClientError
from psycopg2.extras import RealDictCursor

# All environment variables
username = os.environ['username']
password = os.environ['password']
host = os.environ['host']
port = os.environ['port']
database = os.environ['database']

# Initialize the Cognito client
cognito_client = boto3.client('cognito-idp')

def lambda_handler(event, context):
    
    # Extract AccessToken from the authorizationToken field in the event
    token = event.get('authorizationToken')
    
    # To Send the 401 error message when there was not token
    if not token:
        return {
            'statusCode': 401,
            'body': 'AccessToken is required.'
        }
    
    # Initialize the cursor and connect var
    cur = None
    conn = None
    
    try:
        # Validate the AccessToken by calling Cognito
        response = cognito_client.get_user(AccessToken=token)

        email = next(
            (attr['Value'] for attr in response['UserAttributes'] if attr['Name'] == 'email'),
            None
        )
        
        
        # Connect to the PostgreSQL server
        conn  = psycopg2.connect(
            host=host, user=username, password=password, dbname=database, port=port
        )
        
        # Making to the Db cursor
        cur  = conn.cursor()
        
        # Query the admin Modules table
        query = "SELECT user_id FROM admin.users WHERE email = %s;"
        cur.execute(query, (email,))
        user_id_result = cur.fetchone()
        
        # Define a query to get all role_id for the given user_id
        role_query = "SELECT role_id FROM admin.user_roles WHERE user_id = %s;"
    
        # Execute the query with the user_id
        cur.execute(role_query, (user_id_result,))
    
        # Fetch all results
        roles = cur.fetchall()
        
        role_ids = [role_id for role_id, in roles]
        permission_query = """
        SELECT m.module_name, p.access_type
        FROM admin.role_module_permissions p
        JOIN admin.modules m ON p.module_id = m.module_id
        WHERE p.role_id = ANY(%s);
        """
        
        cur.execute(permission_query, (role_ids,))

        # Fetch all results
        permissions = cur.fetchall()
        
        permissions_dict = {}
        for module_name, access_type in permissions:
            if module_name in permissions_dict:
                permissions_dict[module_name].append(access_type)
            else:
                permissions_dict[module_name] = [access_type]
                
                
        # Get user roles from the database
        userRoles = get_user_roles(email,conn)



        # Iterate through the keys in the "permissions" dictionary
        for key, value in permissions_dict.items():
            # Check if the value is a list and contains "fullAccess"
            if isinstance(value, list) and "fullAccess" in value:
                # Add additional permissions if not already present
                additional_permissions = ["delete", "read", "write", "update"]
                for permission in additional_permissions:
                    if permission not in value:
                        value.append(permission)


        if "Super User Readonly" in userRoles:
            # Query the admin Modules table
            moduleNamesQuery = "select module_name from admin.modules"
            cur.execute(moduleNamesQuery)
            modules = cur.fetchall()

            # Initialize a dictionary to store modules with permissions
            modules_with_permissions = {}

            # Iterate over fetched modules and add permissions
            for module in modules:
                module_name = module[0]  # Assuming the module name is in the first column
                modules_with_permissions[module_name] = [
                    "read"
                ]

            # Print the resulting dictionary

            permissions_dict = modules_with_permissions
            permissions_dict["super_user_readonly"] = True
        else:
            permissions_dict["super_user_readonly"] = False

        if "Super user" in userRoles:
            # Query the admin Modules table
            moduleNamesQuery = "select module_name from admin.modules"
            cur.execute(moduleNamesQuery)
            modules = cur.fetchall()

            # Initialize a dictionary to store modules with permissions
            modules_with_permissions = {}

            # Iterate over fetched modules and add permissions
            for module in modules:
                module_name = module[0]  # Assuming the module name is in the first column
                modules_with_permissions[module_name] = [
                    "fullAccess",
                    "delete",
                    "read",
                    "write",
                    "update"
                ]

            # Print the resulting dictionary

            permissions_dict = modules_with_permissions
            permissions_dict["super_user"] = True
        else:
            permissions_dict["super_user"] = False


        if "Privileged User" in userRoles:

            # Query the admin Modules table
            moduleNamesQuery = "select module_name from admin.modules"
            cur.execute(moduleNamesQuery)
            modules = cur.fetchall()

            # Initialize a dictionary to store modules with permissions
            modules_with_permissions = {}

            # Iterate over fetched modules and add permissions
            for module in modules:
                module_name = module[0]  # Assuming the module name is in the first column
                modules_with_permissions[module_name] = [
                    "fullAccess",
                    "delete",
                    "read",
                    "write",
                    "update"
                ]

            # Print the resulting dictionary

            permissions_dict = modules_with_permissions
            permissions_dict["Privileged User"] = True
        else :
            permissions_dict["Privileged User"] = False


        # Check if 'admin' role is in the user's roles
        if "System Administrator" in userRoles:
            permissions_dict["admin"] = True
        else:
            permissions_dict["admin"] = False

        if 'Super user' not in userRoles:
            permissions_dict["super_user"] = False
        if 'Super User Readonly' not in userRoles:
            permissions_dict["super_user_readonly"] = False
        if 'Privileged User' not in userRoles:
            permissions_dict["Privileged User"] = False
        
        
        # If successful, grant access

        print("allow is working...",str(permissions_dict))

        return {
            'principalId': response['Username'],
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': 'Allow',
                        'Resource': "arn:aws:execute-api:ap-southeast-2:320508770855:*/*/*/*"
                    }
                ]
            },
            'context': {
                'username': response['Username'],
                'status': 'confirmed',
                'userId' : str(user_id_result[0]),
                'permissions_dict' : str(permissions_dict)
            }
        }
        
    except psycopg2.Error as db_error:
        error_message = str(db_error)
        return {
            'statusCode': 500,
            'body': json.dumps({"message": "Database operation failed", "error": error_message})
        }
        
    except ClientError as e:
    
        # Deny access if there's an error in token validation

        print("Deny is working...")

        return {
            'principalId': 'User',
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': 'Deny',
                        'Resource': "arn:aws:execute-api:ap-southeast-2:320508770855:*/*/*/*"
                    }
                ]
            }
        }
        
    finally:
        # Close the cursor and connection
        if cur:
            cur.close()
        if conn:
            conn.close()
            
            
def get_user_roles(username,conn):
    
    try:

        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            query = """
            SELECT 
                ARRAY_AGG(r.role_name) AS role_names
            FROM 
                admin.users u
            JOIN 
                admin.user_roles ur ON u.user_id = ur.user_id
            JOIN 
                admin.roles r ON ur.role_id = r.role_id
            WHERE 
                u.email = %s
            GROUP BY 
                u.user_id;
            """
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            if result:
                return result["role_names"]
            else:
                return []
    except Exception as e:
        print(f"Database error: {e}")
        return []