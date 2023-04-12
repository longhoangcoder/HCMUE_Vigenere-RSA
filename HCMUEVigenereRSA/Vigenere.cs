using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HCMUEVigenereRSA
{
    class Vigenere
    {
        #region property
        public string key { get; set; }
        public string plainText { get; set; }
        public string cipherText { get; set; }
        #endregion
        public Vigenere(string s)
        {
            key = s.ToUpper();
        }

        string stringArray = "AĂÂBCDĐEÊFGHIJKLMNOÔƠPQRSTUƯVWXYZÁÀẢÃẠẮẰẲẴẶẤẦẨẪẬÉÈẺẼẸẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌỐỒỔỖỘỚỜỞỠỢÚÙỦŨỤỨỪỬỮỰÝỲỶỸỴ1234567890?`~@#$%^&()_-=/+<>,.|\\';:\"{}[]*! ";
        public int[] stringArrayIndexOf(string s)
        {
            int[] arr = new int[s.Length];
            for (int i = 0; i < s.Length; i++)
                arr[i] = stringArray.IndexOf(s[i]);
            return arr;
        }

        public string stringIndexOf(int[] arr)
        {
            string str = "";
            for (int i = 0; i < arr.Length; i++)
                str += stringArray[arr[i]];
            return str;
        }

        public String Encryption()
        {
            plainText = plainText.ToUpper();
            int[] arrplainText = stringArrayIndexOf(plainText);
            int[] arrKey = stringArrayIndexOf(key);

            int[] result = new int[plainText.Length];
            for (int i = 0, j = 0; i < plainText.Length; i++)
            {
                result[i] = (arrplainText[i] + arrKey[j]) % stringArray.Length;
                j = ++j % arrKey.Length;
            }
            cipherText = stringIndexOf(result);
            return cipherText;
        }

        public String Decryption()
        {
            int[] arrCipherText = stringArrayIndexOf(cipherText);
            int[] arrKey = stringArrayIndexOf(key);

            int[] result = new int[cipherText.Length];
            for (int i = 0, j = 0; i < cipherText.Length; i++)
            {
                result[i] = (arrCipherText[i] - arrKey[j]) % stringArray.Length;
                if (result[i] < 0)
                    result[i] = (arrCipherText[i] + (stringArray.Length - arrKey[j])) % stringArray.Length;
                j = ++j % arrKey.Length;
            }

            plainText = stringIndexOf(result);
            return plainText;
        }
    }
}
