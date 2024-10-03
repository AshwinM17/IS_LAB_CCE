import rsa
import hashlib

class HospitalManagementSystem:
    def __init__(self):
        # Generate RSA keys for the doctor (for signing/updating records)
        self.doctor_public_key, self.doctor_private_key = rsa.newkeys(2048)

        # Generate RSA keys for the admin (for verifying signatures and decrypting records)
        self.admin_public_key, self.admin_private_key = rsa.newkeys(2048)

        # Simulated patient records (can be updated as needed)
        self.patient_records = {}

    def hash_record(self, record):
        """
        Generate a SHA-256 hash of the record.
        """
        return hashlib.sha256(record.encode()).hexdigest() #returs a hex string

    def sign_record(self, patient_id, record):
        """
        Doctor digitally signs the patient record.
        """
        # Hash the record to ensure integrity
        record_hash = self.hash_record(record) #in hex format

        # Sign the hash using the doctor's private key
        signature = rsa.sign(record_hash.encode(), self.doctor_private_key, 'SHA-1')
        
        # Store the signed record
        self.patient_records[patient_id] = {
            'record': record,
            'signature': signature,
            'hash': record_hash #in hex format
        }

        return signature

    def verify_signature(self, patient_id):
        """
        Admin verifies the digital signature of the patient record.
        """
        record_data = self.patient_records.get(patient_id)
        if not record_data:
            return False, "Record not found."

        record = record_data['record']
        signature = record_data['signature']
        record_hash = record_data['hash']

        # Verify the signature using the doctor's public key
        try:
            rsa.verify(record_hash.encode(), signature, self.doctor_public_key)
            return True, "Signature verified successfully."
        except rsa.VerificationError:
            return False, "Signature verification failed."

    def encrypt_record(self, patient_id):
        """
        Encrypt the patient record.
        """
        record_data = self.patient_records.get(patient_id)
        if not record_data:
            return "Record not found."

        record = record_data['record']
        # Encrypt the record using the admin's public key
        encrypted_record = rsa.encrypt(record.encode(), self.admin_public_key)
        
        return encrypted_record

    def decrypt_record(self, encrypted_record):
        """
        Admin decrypts the patient record.
        """
        # Decrypt the record using the admin's private key
        decrypted_record = rsa.decrypt(encrypted_record, self.admin_private_key).decode()
        return decrypted_record

    def get_hashed_value(self, patient_id):
        """
        Nurse can only see the hashed value of the patient record.
        """
        record_data = self.patient_records.get(patient_id)
        if not record_data:
            return "Record not found."
        
        return record_data['hash']


# Example Usage
if __name__ == "__main__":
    hospital_system = HospitalManagementSystem()

    # Doctor signs a patient record
    patient_id = "patient123"
    record = "Patient Name: John Doe, Diagnosis: Flu, Treatment: Rest and hydration."
    signature = hospital_system.sign_record(patient_id, record)
    print(f"Signature for {patient_id}: {signature}")

    # Admin verifies the digital signature
    is_verified, verification_message = hospital_system.verify_signature(patient_id)
    print(verification_message)

    # Admin encrypts the patient record
    encrypted_record = hospital_system.encrypt_record(patient_id)
    print(f"Encrypted record: {encrypted_record}")

    # Admin decrypts the patient record
    decrypted_record = hospital_system.decrypt_record(encrypted_record)
    print(f"Decrypted record: {decrypted_record}")

    # Nurse gets the hashed value of the patient record
    hashed_value = hospital_system.get_hashed_value(patient_id)
    print(f"Hashed value for {patient_id}: {hashed_value}")