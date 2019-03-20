using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Math;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
namespace TestBouncyCastle
{
    class ProgramBackUp
    {
        static void Backup(string[] args)
        {
            /*
            var keyBytes = Convert.FromBase64String("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGhMcl5q5rYKMUuSN0X2GabqahoxP8uar/l+JfmJqYRt9mTcpuE+5aPCuZO9lG4wTD4AkAxXvWCIU0P/e10QrmP+/8bV851q4hXvfVB3XTDutRFDu515XBNYFdQdrcU0C+f/IJtcAC/+YOPzKamXoBE1zCIDZg7xxY4yxnSplILwIDAQAB"); // your key here

            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            byte[] plaintext = Encoding.UTF8.GetBytes("P12345678");
            byte[] ciphertext = rsa.Encrypt(plaintext, false);
            string cipherresult = Convert.ToBase64String(ciphertext);


            Console.WriteLine("Llave Publica: " + Convert.ToBase64String(keyBytes));
            Console.WriteLine("Texto Plano: " + System.Text.Encoding.UTF8.GetString(plaintext));
            Console.WriteLine("Texto Cifrado: " + cipherresult);
            Console.ReadKey();
            */

            ///-------------------------------------------------------------------------------------------------------
            /*
            byte[] keyBytes = Convert.FromBase64String("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIaExyXmrmtgoxS5I3RfYZpupqGjE/y5qv+X4l+YmphG32ZNym4T7lo8K5k72UbjBMPgCQDFe9YIhTQ/97XRCuY/7/xtXznWriFe99UHddMO61EUO7nXlcE1gV1B2txTQL5/8gm1wAL/5g4/MpqZegETXMIgNmDvHFjjLGdKmUgvAgMBAAECgYB+96CJE50Z2NLU4pKmasjTXRGGi0h4SD8wlImktYNlq698/nvNPp7BKP312lmQ4QJEZ5fX1I64TL59vMrwH+lqXBO9Y0C/Jag5xwacFRbawwXNYuaBj992JumAKs8PrfdB3naJLp7e1zD9rw4fSdPMFNuf0qTAVgDoXCiobe+OkQJBANgtLHJhyoCd/mlS9gVfeT3fka5W9O9vUx+7fhtgLPU76+QPJfP9Dja9VXRpA+IjJ3dXJXNZYS1+eM4U2hzJ3wMCQQCfTKTDEeLB8KcyQ2my/Pt9/e59yjKxEhGFhb7AtUrnoPPs01rstfan+AqCz6/+kRqlyCCie0Sozil2SOvmEsRlAkEAmr9rq825KmzvK/JJTvtTTSl3nbd9ytCETpjm4y3rwPlOGYmGf6xMun66Z4StVPoZTGLD2ljHKcv5KnzezfDshQJAcc8qL4vJu9GZQlnTXGNNsjgHeatKCCPmjMR/AeMEPvRJETv3TAK81EhsCgUjsfYtWZ/fYPY8mXWhPbbfgqKJ2QJAW8eKeaLDMDqAjnN+NnJuX5PASUEF5+CkisM4LK/YVvSfhmCawP9AzWGzSw5x9qhsXSQRlD0SJdlNx+EeG3wj/Q=="); // your key here
            MemoryStream strm = new MemoryStream(keyBytes);
            //strm.Write(keyBytes, 0, keyBytes.Length);

            var ciphertext = "ZegvpOhgCmaHhPaCU62BzFyzMtP5+LiPkVVrwuCi7qPgdgPPET8fC+0VDhQQ4vA1QmmOrcH8xYQo94Phs7OXMS8E1jaImu41Fq2e6wqXrqp1JJIc7jmQSXPzqi9bX/AJbgwm5Jt80ZKcmBoUP1BluQ/tkRJpymk00wz3MZyRIEA=";

            //var privKeyObj = Asn1Object.FromStream(strm);
            var privKeyObj = Asn1Sequence.FromByteArray(keyBytes);
            //var privStruct = new RsaPrivateKeyStructure((Asn1Sequence)privKeyObj);
            var privStruct = new RsaPrivateKeyStructure((Asn1Sequence)privKeyObj);

            // Conversion from BouncyCastle to .Net framework types
            var rsaParameters = new RSAParameters();
            rsaParameters.Modulus = privStruct.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = privStruct.PublicExponent.ToByteArrayUnsigned();
            rsaParameters.D = privStruct.PrivateExponent.ToByteArrayUnsigned();
            rsaParameters.P = privStruct.Prime1.ToByteArrayUnsigned();
            rsaParameters.Q = privStruct.Prime2.ToByteArrayUnsigned();
            rsaParameters.DP = privStruct.Exponent1.ToByteArrayUnsigned();
            rsaParameters.DQ = privStruct.Exponent2.ToByteArrayUnsigned();
            rsaParameters.InverseQ = privStruct.Coefficient.ToByteArrayUnsigned();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);
            var result = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(ciphertext), true));
            Console.WriteLine(result);
            Console.ReadKey();
            */
            ///-------------------------------------------------------------------------------------------------------

            /*
            //  Cero forma para decriptar !!! ///
            var bytesToDecrypt = Convert.FromBase64String(string64); // string to decrypt, base64 encoded

            AsymmetricCipherKeyPair keyPair;

            using (var reader = File.OpenText(@"C:\Users\Diego\Documents\private.pem"))
                keyPair = (AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();

            var decryptEngine = new Pkcs1Encoding(RsaEngine());
            decryptEngine.Init(false, keyPair.Private);

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            Logs.Log.LogMessage("decrypted: " + decrypted);
            System.Windows.MessageBox.Show(decrypted);


            //  Primera  forma para decriptar !!! ///
            keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            IAsymmetricBlockCipher cipher = new RsaEngine();
            RsaKeyParameters privateKey = (RsaKeyParameters)keyPair.Private;
            cipher.Init(false, keyPair.Private);
            byte[] deciphered = cipher.ProcessBlock(bytesl, 0, bytesl.Length);
            string decipheredText = utf8enc.GetString(deciphered);

            // Segunda forma para decritar !!!  //
            UTF8Encoding utf8enc = new UTF8Encoding();
            FileStream encryptedFile = null;
            StreamWriter plainFile = null;
            byte[] encryptedBytes = null;
            string plainText = "";
            AsymmetricCipherKeyPair keyPair;
            using (var reader = File.OpenText(privateKeyFileName))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            //return keyPair.Private;
            AsymmetricKeyParameter key = readPrivateKey(keyPair.Private);
            RsaEngine e = new RsaEngine();
            e.Init(false, key);
            byte[] decipheredBytes = e.ProcessBlock(cipheredData, 0, cipheredData.Length);
            */

            //BigInteger mod = new BigInteger("AQAB");
            //BigInteger pubExp = new BigInteger("hoTHJeaua2CjFLkjdF9hmm6moaMT/Lmq/5fiX5iamEbfZk3KbhPuWjwrmTvZRuMEw+AJAMV71giFND/3tdEK5j/v/G1fOdauIV731Qd10w7rURQ7udeVwTWBXUHa3FNAvn/yCbXAAv/mDj8ympl6ARNcwiA2YO8cWOMsZ0qZSC8=");
            //BigInteger privExp = new BigInteger("fvegiROdGdjS1OKSpmrI010RhotIeEg/MJSJpLWDZauvfP57zT6ewSj99dpZkOECRGeX19SOuEy+fbzK8B/palwTvWNAvyWoOccGnBUW2sMFzWLmgY/fdibpgCrPD633Qd52iS6e3tcw/a8OH0nTzBTbn9KkwFYA6FwoqG3vjpE=");
            //BigInteger p = new BigInteger("2C0scmHKgJ3+aVL2BV95Pd+Rrlb0729TH7t+G2As9Tvr5A8l8/0ONr1VdGkD4iMnd1clc1lhLX54zhTaHMnfAw==");
            //BigInteger q = new BigInteger("n0ykwxHiwfCnMkNpsvz7ff3ufcoysRIRhYW+wLVK56Dz7NNa7LX2p/gKgs+v/pEapcggontEqM4pdkjr5hLEZQ==");
            //BigInteger pExp = new BigInteger("mr9rq825KmzvK/JJTvtTTSl3nbd9ytCETpjm4y3rwPlOGYmGf6xMun66Z4StVPoZTGLD2ljHKcv5KnzezfDshQ==");
            //BigInteger qExp = new BigInteger("cc8qL4vJu9GZQlnTXGNNsjgHeatKCCPmjMR/AeMEPvRJETv3TAK81EhsCgUjsfYtWZ/fYPY8mXWhPbbfgqKJ2Q==");
            //BigInteger crtCoef = new BigInteger("W8eKeaLDMDqAjnN+NnJuX5PASUEF5+CkisM4LK/YVvSfhmCawP9AzWGzSw5x9qhsXSQRlD0SJdlNx+EeG3wj/Q==");

            //RsaKeyParameters privParameters = new RsaPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);
            //RsaKeyParameters pubParameters = new RsaKeyParameters(false, mod, pubExp);
            //IAsymmetricBlockCipher eng = new Pkcs1Encoding(new RsaEngine());
            //eng.Init(false, privParameters);
            //byte[] encdata = System.Convert.FromBase64String("ZegvpOhgCmaHhPaCU62BzFyzMtP5+LiPkVVrwuCi7qPgdgPPET8fC+0VDhQQ4vA1QmmOrcH8xYQo94Phs7OXMS8E1jaImu41Fq2e6wqXrqp1JJIc7jmQSXPzqi9bX/AJbgwm5Jt80ZKcmBoUP1BluQ/tkRJpymk00wz3MZyRIEA=");
            //encdata = eng.ProcessBlock(encdata, 0, encdata.Length);
            //string result = Encoding.UTF8.GetString(encdata);
            //Console.WriteLine(result);
            string strt1 = "P123456789";
            string strt2 = "fwsLM9Upzvv1RUMr8FQzm3Z3SLjxh3cn4U0IKSSzIaZ9Wt+guLO0GPHyMWjU4qLl1lw3nS3j2bFJ7AKks657DMlnpwM56DTs558iGPKRe8TXpsi/TNdJiCKx1fi2G8z7ny4o1oIDxpAwuJ5CJKGVo6MiybhDjdu/4WKSEoatQfY=";

            //Console.WriteLine(Encryption(strt1));
            //Console.ReadKey();

            //Console.WriteLine(Decryption(Encryption(strt1)));
            //Console.WriteLine(Decryption(strt2));

            var privateKey = "<RSAKeyValue><Modulus>hoTHJeaua2CjFLkjdF9hmm6moaMT/Lmq/5fiX5iamEbfZk3KbhPuWjwrmTvZRuMEw+AJAMV71giFND/3tdEK5j/v/G1fOdauIV731Qd10w7rURQ7udeVwTWBXUHa3FNAvn/yCbXAAv/mDj8ympl6ARNcwiA2YO8cWOMsZ0qZSC8=</Modulus><Exponent>AQAB</Exponent><P>2C0scmHKgJ3+aVL2BV95Pd+Rrlb0729TH7t+G2As9Tvr5A8l8/0ONr1VdGkD4iMnd1clc1lhLX54zhTaHMnfAw==</P><Q>n0ykwxHiwfCnMkNpsvz7ff3ufcoysRIRhYW+wLVK56Dz7NNa7LX2p/gKgs+v/pEapcggontEqM4pdkjr5hLEZQ==</Q><DP>mr9rq825KmzvK/JJTvtTTSl3nbd9ytCETpjm4y3rwPlOGYmGf6xMun66Z4StVPoZTGLD2ljHKcv5KnzezfDshQ==</DP><DQ>cc8qL4vJu9GZQlnTXGNNsjgHeatKCCPmjMR/AeMEPvRJETv3TAK81EhsCgUjsfYtWZ/fYPY8mXWhPbbfgqKJ2Q==</DQ><InverseQ>W8eKeaLDMDqAjnN+NnJuX5PASUEF5+CkisM4LK/YVvSfhmCawP9AzWGzSw5x9qhsXSQRlD0SJdlNx+EeG3wj/Q==</InverseQ><D>fvegiROdGdjS1OKSpmrI010RhotIeEg/MJSJpLWDZauvfP57zT6ewSj99dpZkOECRGeX19SOuEy+fbzK8B/palwTvWNAvyWoOccGnBUW2sMFzWLmgY/fdibpgCrPD633Qd52iS6e3tcw/a8OH0nTzBTbn9KkwFYA6FwoqG3vjpE=</D></RSAKeyValue>";
            byte[] encrypted = Convert.FromBase64String("UowcVCIEoqi4RmW3pRfDUYldYfNwrgasXmPAGml2t6vx2VDNRmHmDRFYksPjOcDHYd9HAC6QCEfWjSi7I9cBTvs1metw+GI1e9gU0p/FpDWwHnHUugqFrJzmhy9U0ee5zZURCsWaK0t97AwPbZY1bLLSAv1IFpwxT+upf0e+YaI=");
            byte[] decipt = decryptRSA(encrypted, privateKey);
            var decryptedData = Encoding.UTF8.GetString(decipt);

            Console.WriteLine(decryptedData.ToString());
            Console.ReadKey();
        }




        //public static string Decryption(string strText)
        public static byte[] decryptRSA(byte[] encrypted, string privateKey)
        {

            //var privateKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent><P>/aULPE6jd5IkwtWXmReyMUhmI/nfwfkQSyl7tsg2PKdpcxk4mpPZUdEQhHQLvE84w2DhTyYkPHCtq/mMKE3MHw==</P><Q>3WV46X9Arg2l9cxb67KVlNVXyCqc/w+LWt/tbhLJvV2xCF/0rWKPsBJ9MC6cquaqNPxWWEav8RAVbmmGrJt51Q==</Q><DP>8TuZFgBMpBoQcGUoS2goB4st6aVq1FcG0hVgHhUI0GMAfYFNPmbDV3cY2IBt8Oj/uYJYhyhlaj5YTqmGTYbATQ==</DP><DQ>FIoVbZQgrAUYIHWVEYi/187zFd7eMct/Yi7kGBImJStMATrluDAspGkStCWe4zwDDmdam1XzfKnBUzz3AYxrAQ==</DQ><InverseQ>QPU3Tmt8nznSgYZ+5jUo9E0SfjiTu435ihANiHqqjasaUNvOHKumqzuBZ8NRtkUhS6dsOEb8A2ODvy7KswUxyA==</InverseQ><D>cgoRoAUpSVfHMdYXW9nA3dfX75dIamZnwPtFHq80ttagbIe4ToYYCcyUz5NElhiNQSESgS5uCgNWqWXt5PnPu4XmCXx6utco1UVH8HGLahzbAnSy6Cj3iUIQ7Gj+9gQ7PkC434HTtHazmxVgIR5l56ZjoQ8yGNCPZnsdYEmhJWk=</D></RSAKeyValue>";

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            if (encrypted == null)
            {
                throw new Exception("Data is empty");
            }
            if (encrypted.Length == 0)
            {
                throw new Exception("Data length is zero");
            }
            if (privateKey == null)
            {
                throw new Exception("Certificate Private Key is empty");
            }
            //if (RSA.SignatureAlgorithm.Equals("http://www.w3.org/2000/09/xmldsig#rsa-sha1") ) {
            //           throw new Exception("Certificate Algorithm is not RSA");
            //       }      RSA.SignatureAlgorithm always is "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            try
            {

                RSA.FromXmlString(privateKey);
                //  Formato codificacion OaepSHA1 --> RSA/ECB/OAEPWithSHA-1AndMGF1Padding
                // Formato codificacion Pkcs1  --> RSA --> RSA / ECB / PKCS1Padding
                return RSA.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);

                //byte[] encryptionByte = null;
                //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                //cipher.init(2, privateKey);
                //byte[] someDecrypted = cipher.update(encrypted);
                //byte[] moreDecrypted = cipher.doFinal();
                //byte[] decrypted = new byte[someDecrypted.length + moreDecrypted.length];
                //System.arraycopy(someDecrypted, 0, decrypted, 0, someDecrypted.length);
                //System.arraycopy(moreDecrypted, 0, decrypted, someDecrypted.length, moreDecrypted.length);
                //return decrypted;
            }
            catch (Exception ex)
            {
                throw ex;
            }

            //var testData = Encoding.UTF8.GetBytes(strText);

            //using (var rsa = new RSACryptoServiceProvider(1024))
            //{
            //    try
            //    {
            //        var base64Encrypted = strText;

            //        // server decrypting data with private key                    
            //        rsa.FromXmlString(privateKey);

            //        var resultBytes = Convert.FromBase64String(base64Encrypted);
            //        var decryptedBytes = rsa.Decrypt(resultBytes, true);
            //        var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
            //        return decryptedData.ToString();
            //    }
            //    finally
            //    {
            //        rsa.PersistKeyInCsp = false;
            //    }
            //}
        }



        public static string Encryption(string strText)
        {
            //var publicKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            var publicKey = "<RSAKeyValue><Modulus>hoTHJeaua2CjFLkjdF9hmm6moaMT/Lmq/5fiX5iamEbfZk3KbhPuWjwrmTvZRuMEw+AJAMV71giFND/3tdEK5j/v/G1fOdauIV731Qd10w7rURQ7udeVwTWBXUHa3FNAvn/yCbXAAv/mDj8ympl6ARNcwiA2YO8cWOMsZ0qZSC8=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            var testData = Encoding.UTF8.GetBytes(strText);

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    // client encrypting data with public key issued by server                    
                    rsa.FromXmlString(publicKey.ToString());

                    var encryptedData = rsa.Encrypt(testData, true);

                    var base64Encrypted = Convert.ToBase64String(encryptedData);

                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }


    }
}

