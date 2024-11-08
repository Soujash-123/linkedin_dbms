import requests
import json

BASE_URL = "https://syntalix-mail.onrender.com/api"

def login(email, password):
    url = f"{BASE_URL}/login"
    headers = {"Content-Type": "application/json"}
    payload = {
        "email": email,
        "password": password
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        session_id = response.json().get("session_id")
        print(f"Logged in successfully! Session ID: {session_id}")
        return session_id
    else:
        print(f"Login failed: {response.json().get('message')}")
        return None

def send_email(session_id, to, subject, content, attachments=[]):
    url = f"{BASE_URL}/send_email"
    headers = {
        "Content-Type": "application/json",
        "Session-ID": session_id
    }
    payload = {
        "to": to,
        "subject": subject,
        "content": content,
        "attachments": attachments
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        print("Email sent successfully!")
    else:
        print(f"Failed to send email: {response.json().get('message')}")

def fetch_emails(session_id):
    url = f"{BASE_URL}/fetch_emails"
    headers = {
        "Content-Type": "application/json",
        "Session-ID": session_id
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        emails = response.json()
        if emails:
            print("Fetched emails:")
            for email in emails:
                print(f"From: {email['sender']}, Subject: {email['subject']}, Content: {email['content']}")
        else:
            print("No emails found.")
    else:
        print(f"Failed to fetch emails: {response.json().get('message')}")

def main():
    email = "soujash@syntalix.user"  # Replace with a valid email from your DB
    password = "Mana@1978"  # Replace with the correct password

    # Step 1: Login
    session_id = login(email, password)
    if not session_id:
        return

    # Step 2: Send email (replace 'to_email' with a valid recipient)
    send_email(session_id, "recipient@syntalix.user", "Test Subject", "This is a test email.")

    # Step 3: Fetch emails
    fetch_emails(session_id)

if __name__ == "__main__":
    main()

