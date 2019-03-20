using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Utilerias
{
    public class ConvertRsa
    {
        public string DecryptRSA(byte[] encrypted)
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
                byte[] decript = RSA.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
                var decryptedencoding = Encoding.UTF8.GetString(decript);
                string decryptedata = decryptedencoding.ToString();
                return decryptedata;
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
    }
}
