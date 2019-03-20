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
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Escribe la cadena a cifrar...");

            string strt1 = Console.ReadLine();

            Console.WriteLine("Texto plano: " + strt1);

            Console.ReadKey();
            var encript = EncryptionRSA(strt1);

            Console.WriteLine("Cadena encriptada: " + encript);

            Console.ReadKey();

            byte[] encrypted = Convert.FromBase64String(encript);

            //Incluir la cadena encriptada
            //byte[] encrypted = Convert.FromBase64String("SZcaK48hD5pb2czYrR0b2MGfIThLvuUFcGH58EPKvVZNdBcJmlEluPI9bYESiAnCRJCJjDKHpOovh8XZ7SDFUMBhIO0SArw3Y2Qj3Godyn3LnutsAdqBUOL1IP9d3Oluay46DaHDUGHSu/BvnYbApj6nVVUEpfzIfeDKwEyinAY=");

            byte[] decript = DecryptRSA(encrypted);

            var decryptedData = Encoding.UTF8.GetString(decript);
           
            Console.WriteLine("Cadena Dsencriptada: " + decryptedData.ToString());

            Console.ReadKey();

        }


        public static byte[] DecryptRSA(byte[] encrypted)
        {
            var privateKey = "<RSAKeyValue><Modulus>hoTHJeaua2CjFLkjdF9hmm6moaMT/Lmq/5fiX5iamEbfZk3KbhPuWjwrmTvZRuMEw+AJAMV71giFND/3tdEK5j/v/G1fOdauIV731Qd10w7rURQ7udeVwTWBXUHa3FNAvn/yCbXAAv/mDj8ympl6ARNcwiA2YO8cWOMsZ0qZSC8=</Modulus><Exponent>AQAB</Exponent><P>2C0scmHKgJ3+aVL2BV95Pd+Rrlb0729TH7t+G2As9Tvr5A8l8/0ONr1VdGkD4iMnd1clc1lhLX54zhTaHMnfAw==</P><Q>n0ykwxHiwfCnMkNpsvz7ff3ufcoysRIRhYW+wLVK56Dz7NNa7LX2p/gKgs+v/pEapcggontEqM4pdkjr5hLEZQ==</Q><DP>mr9rq825KmzvK/JJTvtTTSl3nbd9ytCETpjm4y3rwPlOGYmGf6xMun66Z4StVPoZTGLD2ljHKcv5KnzezfDshQ==</DP><DQ>cc8qL4vJu9GZQlnTXGNNsjgHeatKCCPmjMR/AeMEPvRJETv3TAK81EhsCgUjsfYtWZ/fYPY8mXWhPbbfgqKJ2Q==</DQ><InverseQ>W8eKeaLDMDqAjnN+NnJuX5PASUEF5+CkisM4LK/YVvSfhmCawP9AzWGzSw5x9qhsXSQRlD0SJdlNx+EeG3wj/Q==</InverseQ><D>fvegiROdGdjS1OKSpmrI010RhotIeEg/MJSJpLWDZauvfP57zT6ewSj99dpZkOECRGeX19SOuEy+fbzK8B/palwTvWNAvyWoOccGnBUW2sMFzWLmgY/fdibpgCrPD633Qd52iS6e3tcw/a8OH0nTzBTbn9KkwFYA6FwoqG3vjpE=</D></RSAKeyValue>";

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

            try
            {

                RSA.FromXmlString(privateKey);
                //  Formato codificacion OaepSHA1 --> RSA/ECB/OAEPWithSHA-1AndMGF1Padding
                // Formato codificacion Pkcs1  --> RSA --> RSA / ECB / PKCS1Padding
                return RSA.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }


        //Verificar el formato de encriptacion
        public static string EncryptionRSA(string strText)
        {
            var publicKey = "<RSAKeyValue><Modulus>hoTHJeaua2CjFLkjdF9hmm6moaMT/Lmq/5fiX5iamEbfZk3KbhPuWjwrmTvZRuMEw+AJAMV71giFND/3tdEK5j/v/G1fOdauIV731Qd10w7rURQ7udeVwTWBXUHa3FNAvn/yCbXAAv/mDj8ympl6ARNcwiA2YO8cWOMsZ0qZSC8=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            var testData = Encoding.UTF8.GetBytes(strText);

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    // client encrypting data with public key issued by server                    
                    rsa.FromXmlString(publicKey.ToString());

                    var encryptedData = rsa.Encrypt(testData, RSAEncryptionPadding.Pkcs1);

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
    