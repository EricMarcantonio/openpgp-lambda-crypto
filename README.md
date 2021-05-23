# OPENPGP-LAMBDA-CRYPTO

This repo targets best practices in the :cloud: .



#### TL;DR

Everything stored in the cloud should be secured. This code takes an encrypted file and its key, decrypts it, and stores it in the original bucket.

This is simply a POC, and should be changed to your use case.

#### Expanded Description

Let's start off with a use case; you have files that need to be stored in a bucket. These files should be encrypted. We need to take this file and decrypt it to another bucket.

For this we will use PGP, AWS Secrets, AWS S3, AWS Lambda and NodeJS. To get started, we need to understand some of the basics of encryption.

Asymmetrical Cryptography is **not** **safe** to use for large files. If you would like to encrypt a large file, and have the benefits of a public-private key system, you should encrypt the file symmetrically with a key, and then encrypt that key with the public. We do the opposite to decrypt: we take the encrypted secret, decrypt it with the private key, and then use that secret to decrypt the file.

That is what we are doing in this project. Some outside source creates 2 objects in our bucket, one containing the encrypted key, and one containing the encrypted file. We pull the private key from AWS Secrets, and then use that to decrypt the secrets file (ending with `.key.enc`). We then use the secret created from this, to decrypt the file.

I made heavy use of streams throughout this project as it allows for large files to be decrypted without loading it into memory. It also keeps us more secure, but not saving any data (encrypted or decrypted) to the file system. **We are taking an encrypted stream and decrypting it and writing it to an s3 bucket at the same time**. One of the key features of the project.

This function as been tested with a 1.7 MB file, and it took about 9s on a 128MB Lambda Function. This function is triggered on an Object Created in an S3 bucket.

