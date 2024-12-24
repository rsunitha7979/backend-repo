import json
import psycopg2.extras
import os
 
DB_HOST = 'pallasaipsqldb.cim5s2kxz2sw.ap-southeast-2.rds.amazonaws.com'
DB_NAME = 'sridevi_testing'
DB_USER = 'admin_user'
DB_PASSWORD = 'Pa!!a3A!123admin'
DB_PORT = '5432'
 
def lambda_handler(event, context):
    # print("eve",event)
    try:
        action = event.get('action', '')
        print("================")
        # print(event)
        # action = event.get('queryStringParameters', {}).get('action', '')
       
       
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT
        )
 
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # create_table(cursor)
       
        # Handle different actions
        if action == 'create':
            create_result = create_table(cursor)
            return {
                'statusCode': 200,
                'body': json.dumps(create_result)
            }
 
        elif action == 'insert':
            name = event.get('name')
            age = event.get('age')
            salary = event.get('salary')
 
            # create_table_query = '''
            # CREATE TABLE IF NOT EXISTS employees (
            #     name VARCHAR(100),
            #     age INT,
            #     salary DECIMAL(10, 2)
            # );
            # '''
            # cursor.execute(create_table_query)
            insert_result = insert_employee(cursor, name, age, salary)
           
            conn.commit()
 
            return {
                'statusCode': 200,
                'body': json.dumps(insert_result)
            }
 
        elif action == 'read':
            # Read all employees from the table
            read_result = read_employees(cursor)
           
            return {
                'statusCode': 200,
                'body': json.dumps(read_result)
            }
        elif action == 'update':
            name = event.get('name')
            age = event.get('age')
            salary = event.get('salary')
            read_result = update_employee(cursor,name,age,salary)
           
            return {
                'statusCode': 200,
                'body': json.dumps(read_result)
                }
        elif action == 'delete':
            name = event.get('name')
            delete_result = delete_employee(cursor, name)
            return {
                'statusCode': 200,
                'body': json.dumps(delete_result)
            }
       
        else:
            return {
                'statusCode': 200,
                'body': json.dumps("Invalid action. Please specify 'insert' or 'read'.")
            }
       
 
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 200,
            'body': json.dumps(f"Error occurred: {str(e)}")
        }
 
    finally:
        cursor.close()
        conn.close()
       
def create_table(cursor):
    try:
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS employees (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age INT,
            salary DECIMAL(10, 2)
        );
        '''
        cursor.execute(create_table_query)
        print("Table created or already exists.")
        return "Table created or already exists."
    except Exception as e:
        print(f"Error creating table: {str(e)}")
        return f"Error: {str(e)}"
 
def insert_employee(cursor, name, age, salary):
    try:
        insert_query = '''
        INSERT INTO employees (name, age, salary)
        VALUES (%s, %s, %s)
        RETURNING name;
        '''
 
        cursor.execute(insert_query, (name, age, salary))
        inserted_name = cursor.fetchone()[0]  # Retrieve the inserted employee's name
        return f"Employee {inserted_name} inserted successfully."
 
    except Exception as e:
        return f"Error: {str(e)}"
 
def read_employees(cursor):
    try:
        select_query = '''
        SELECT * FROM employees;
        '''
        cursor.execute(select_query)
       
        # Fetch all rows from the result
        rows = cursor.fetchall()
        print(rows)
 
        employees = []
        for row in rows:
            employee = {
                'name': row['name'],
                'age': row['age'],
                'salary': float(row['salary']) if row['salary'] is not None else None
                }
            employees.append(employee)
 
        return employees
 
    except Exception as e:
        return f"Error: {str(e)}"
       
def update_employee(cursor, name, age, salary):
    try:
        update_query = '''
        UPDATE employees
        SET age = %s, salary = %s
        WHERE name = %s
        RETURNING name, age, salary;
        '''
        cursor.execute(update_query, (age, salary, name))
        updated_employee = cursor.fetchone()
 
        if updated_employee:
            return f"Employee {updated_employee['name']} updated to age {updated_employee['age']} with salary {updated_employee['salary']}"
        else:
            return "Employee not found"
 
    except Exception as e:
        return f"Error: {str(e)}"
       
def delete_employee(cursor, name):
    try:
        delete_query = '''
        DELETE FROM employees
        WHERE name = %s
        RETURNING name;
        '''
        cursor.execute(delete_query, (name,))
        deleted_employee = cursor.fetchone()
 
        if deleted_employee:
            return f"Employee {deleted_employee['name']} deleted successfully."
        else:
            return "Employee not found."
 
    except Exception as e:
        return f"Error: {str(e)}"