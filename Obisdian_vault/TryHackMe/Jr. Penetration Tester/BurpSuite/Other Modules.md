## Decoder
The Decoder module of Burp Suite gives user data manipulation capabilities. As implied by its name, it not only decodes data intercepted during an attack but also provides the function to encode our own data, prepping it for transmission to the target. Decoder also allows us to create hashsums of data, as well as providing a Smart Decode feature, which attempts to decode provided data recursively until it is back to being plaintext.

a) **Encoding/Decoding**:
![[Pasted image 20240619190640.png]]

- **Plain**: This refers to the raw text before any transformations are applied.
    
- **URL**: URL encoding is utilized to ensure the safe transfer of data in the URL of a web request. It involves substituting characters for their ASCII character code in hexadecimal format, preceded by a percentage symbol (%). This method is vital for any type of web application testing.
    
    For instance, encoding the forward-slash character (**/**), whose ASCII character code is 47, converts it to **2F** in hexadecimal, thus becoming **%2F** in URL encoding. The Decoder can be used to verify this by typing a forward slash in the input box, then selecting`Encode as -> URL`

- **HTML**: HTML Entities encoding replaces special characters with an ampersand (&), followed by either a hexadecimal number or a reference to the character being escaped, and ending with a semicolon (;). This method ensures the safe rendering of special characters in HTML and helps prevent attacks such as XSS. The HTML option in Decoder allows any character to be encoded into its HTML escaped format or decode captured HTML entities. For instance, to decode a previously discussed quotation mark, input the encoded version and choose `Decode as -> HTML`

- **Base64**: Base64, a commonly used encoding method, converts any data into an ASCII-compatible format. The under-the-hood functioning isn't crucial at this stage; however, interested individuals can find the underlying mathematics [here](https://stackabuse.com/encoding-and-decoding-base64-strings-in-python).
    
- **ASCII Hex**: This option transitions data between ASCII and hexadecimal representations. For instance, the word "ASCII" can be converted into the hexadecimal number "4153434949". Each character is converted from its numeric ASCII representation into hexadecimal.
    
- **Hex, Octal, and Binary**: These encoding methods apply solely to numeric inputs, converting between decimal, hexadecimal, octal (base eight), and binary representations.
    
- **Gzip**: Gzip compresses data, reducing file and page sizes before browser transmission. Faster load times are highly desirable for developers looking to enhance their SEO score and avoid user inconvenience. Decoder facilitates the manual encoding and decoding of gzip data, although it often isn't valid ASCII/Unicode. 
   
b) **Hashing**:
							![[Pasted image 20240619190750.png]]

`Hash`In addition to its Encoding/Decoding functionality, Decoder also offers the ability to generate hashsums for our data.

Hashing is a one-way process that transforms data into a unique signature. For a function to qualify as a hashing algorithm, the output it generates must be irreversible. A proficient hashing algorithm ensures that every data input will generate a completely unique hash. For instance, using the MD5 algorithm to produce a hashsum for the text "MD5sum" returns `4ae1a02de5bd02a5515f583f4fca5e8c`. Using the same algorithm for "MD5SUM" yields an entirely different hash despite the close resemblance of the input: `13b436b09172400c9eb2f69fbd20adad`. Therefore, hashes are commonly used to verify the integrity of files and documents, as even a tiny alteration to the file significantly changes the hashsum.

Hashes are used to securely store passwords since the one-way hashing process makes the passwords relatively secure, even if the database is compromised. When a user creates a password, the application hashes and stores it. During login, the application hashes the submitted password and compares it against the stored hash; if they match, the password is correct. Using this method, an application never needs to store the original (plaintext) password.

![[Pasted image 20240619190737.png]]
## Comparer
Comparer, as the name implies, lets us compare two pieces of data, either by ASCII words or by bytes.
![[Pasted image 20240619190849.png]]

![[Pasted image 20240619190859.png]]


## Sequencer



