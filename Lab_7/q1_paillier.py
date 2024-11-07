import random
from sympy import mod_inverse, nextprime

class Paillier:
    def __init__(self, bit_length=512):
        # Generate two distinct large prime numbers p and q
        self.p = nextprime(random.getrandbits(bit_length))
        self.q = nextprime(random.getrandbits(bit_length))
        
        # Compute n as the product of p and q
        self.n = self.p * self.q
        
        # Compute n squared
        self.n_squared = self.n * self.n
        
        # g is set to n + 1
        self.g = self.n + 1 
        
        # Calculate lambda(n), the least common multiple of (p-1) and (q-1)
        self.lambda_n = (self.p - 1) * (self.q - 1)
        
        # Calculate mu, the modular inverse of lambda(n) modulo n
        self.mu = mod_inverse(self.lambda_n, self.n)

    def encrypt(self, plaintext):
        # Generate a random integer r in the range [1, n-1]
        r = random.randint(1, self.n - 1)
        
        # Compute c1 as g^plaintext mod n_squared
        c1 = pow(self.g, plaintext, self.n_squared)
        
        # Compute c2 as r^n mod n_squared
        c2 = pow(r, self.n, self.n_squared)
        
        # Return the ciphertext as the product of c1 and c2 mod n_squared
        return (c1 * c2) % self.n_squared

    def decrypt(self, ciphertext):
        # Compute u as (ciphertext^lambda(n) - 1) / n
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n
        
        # Recover the plaintext by multiplying u with mu mod n
        plaintext = (u * self.mu) % self.n
        return plaintext

    def add_encrypted(self, c1, c2):
        # Perform homomorphic addition on two ciphertexts
        return (c1 * c2) % self.n_squared
    def subtract_encrypted(self, c1, c2):
        # Compute the modular inverse of c2 mod n_squared
        c2_inv = mod_inverse(c2, self.n_squared)
        # Return the product of c1 and c2_inv mod n_squared
        return (c1 * c2_inv) % self.n_squared
    
    def is_greater_encrypted(self, c1, c2):
        # Subtract c2 from c1 homomorphically
        encrypted_difference = self.subtract_encrypted(c1, c2)
        # Decrypt the result
        decrypted_difference = self.decrypt(encrypted_difference)
        # Check if the decrypted difference is positive
        return decrypted_difference > 0

if __name__ == "__main__":
    # Instantiate the Paillier cryptosystem
    paillier = Paillier()

    # Encrypt two integers
    plaintext1 = 35
    plaintext2 = 25
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    # Print the resulting ciphertexts
    print("Ciphertext 1:", ciphertext1)
    print("Ciphertext 2:", ciphertext2)

    # Perform addition on the encrypted integers
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    print("Encrypted Sum:", encrypted_sum)

    # Decrypt the result of the addition
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print("Decrypted Sum:", decrypted_sum)

    
    # Verify it matches the sum of the original integers
    original_sum = plaintext1 + plaintext2
    print("Original Sum:", original_sum)
    print("Verification:", decrypted_sum == original_sum)

    encrypted_diff=paillier.subtract_encrypted(ciphertext1, ciphertext2)
    decrypted_diff=paillier.decrypt(encrypted_diff)
    print("Decrypted Difference:", decrypted_diff)

    is_greater = paillier.is_greater_encrypted(ciphertext1, ciphertext2)
    print("Is Ciphertext 1 greater than Ciphertext 2:", is_greater)
    '''
    Ciphertext 1: 3653018541427117186365109123105054017149446540590768615764739567884048431924896988696234885550971458249946106884541024772858480179494434253495017870588681764596307797984024143309097924266325762862476182041211170568245809864077979188169682709617928417031438485979810603136665221455404436039519181509126809778625494978743085771407152568226650735396003673861226344690054216645547946165104673597601709100575629858540346348374142032776761064924292659551615461318665405120581625448289483820326646648316791191034764410594623867585418228252267130531129586664530224117503053244853896012698364608648710180584465034629855344787
Ciphertext 2: 232383519165858393442660529325624894783068420032446748226257041762829991599247091036064504633029825520784364551160918382732127257369523004662624087956040685034479888546056146761101097780278396569887880766390120828007534607088690451036533270214955652643772094849255086281304650814327585129314185252454555067765956653252420147119335063121795894944560713695380104091714268834676395538480861917236193157729604031488198811273592488393687326180730234662129569301860416999052104102699957202250628928271962228146318102405666826922298118837025019575031644546655050736606433156298469640159769607926258270384879047053478478531
Encrypted Sum: 2793641812899607047265966071453215278911197811557779219811420410866333153129869097687463980642254199043288028272685082288711425014948918090511577502444715416498411278106589417999735680113477341536787740168815841921502625189747275026573202041262410109544544022198156043058887417589551363919729785006045399804981600425971772472687579438936424686155921550046064181885916421565235486702859897509715152721235249179713767233558812048323699182829327171350485467922639918892435413528481343536757431119140948023682815819400464360560001932993355248039131149174354447916508205509353875556597531758392357476052418423138284940442
Decrypted Sum: 40
Original Sum: 40
Verification: True
    '''