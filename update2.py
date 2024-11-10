import sqlite3

# Connect to the database
conn = sqlite3.connect('jobportal.db')
cursor = conn.cursor()

cursor.execute('DROP TABLE job_listings')
user = cursor.fetchone()
print(user)
# Commit the changes and close the connection
conn.commit()
conn.close()
