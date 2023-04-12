using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

namespace HCMUEVigenereRSA
{
    public partial class VigenereRSA : Form
    {
        public VigenereRSA()
        {
            InitializeComponent();
        }


        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text == "")
            {
                MessageBox.Show("Bạn chưa nhập chuỗi cần mã hóa!");
            }
            else if (textBox2.Text == "")
            {
                MessageBox.Show("Bạn chưa nhập từ khóa!");
            }
            else
            {
                Vigenere vigenere = new Vigenere(textBox2.Text.Trim());
                vigenere.plainText = textBox1.Text.Trim();
                textBox3.Text = vigenere.Encryption();
                textBox4.Text = vigenere.Decryption();
                if (textBox1.Text == textBox4.Text)
                {
                    label5.Text = "Kết quả: Thành công. Bản rõ trùng khớp với chuỗi cần mã hóa.";
                }
                else
                {
                    label5.Text = "Kết quả: Thất bại. Bản rõ không trùng khớp với chuỗi cần mã hóa.";
                }
            }
        }

        private void textBox1_Leave(object sender, EventArgs e)
        {
            textBox1.Text = textBox1.Text.ToUpper();
        }

        private void textBox2_Leave(object sender, EventArgs e)
        {
            textBox2.Text = textBox2.Text.ToUpper();
        }


        private delegate void btnEncryptDecrypt();

        private void numericUpDown1_ValueChanged(object sender, EventArgs e)
        {

            if (numericUpDown1.Value % 8 != 0)
            {
                MessageBox.Show("Kích thước khóa (tính bằng bit) là bội số của 8, và có giá trị từ 384 bit đến 16384 bit");
                numericUpDown1.Value -= numericUpDown1.Value % 8;
            }
        }

        public bool check(int nb)
        {
            if (nb == 2) return false;
            for (int i = 2; i <= nb / 2; i++)
            {
                if (nb % i == 0)
                {
                    return true;
                }
            }
            return false;
        }

        public int createKey(int nb)
        {
            int key = 0;
            for (int i = nb - 1; i >= 2; i--)
            {
                if (!check(i))
                {
                    key = i;
                    break;
                }
            }

            if (key == 0)
            {
                for (int i = nb + 1; i <= 100000; i++)
                {
                    if (!check(i))
                    {
                        key = i;
                        break;
                    }
                }
            }

            return key;
        }


        private void button3_Click(object sender, EventArgs e)
        {

            // Tạo file chứa key
            SaveFileDialog saveFileDialog1 = new SaveFileDialog();
            // saveFileDialog1.DefaultExt = "xml";
            saveFileDialog1.Filter = "All File|*.*";
            saveFileDialog1.Title = "Chọn tên file";
            if (saveFileDialog1.ShowDialog() != DialogResult.OK)
            {
                return;
            }
            try
            {
                //Create a new RSACryptoServiceProvider object.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(int
                    .Parse(numericUpDown1.Value.ToString())))
                {

                    saveFileDialog1.RestoreDirectory = true;
                    String pathPrivateKey = saveFileDialog1.FileName + "_PrivateKey.xml";
                    String pathPublicKey = saveFileDialog1.FileName + "_PublicKey.xml";

                    File.WriteAllText(pathPrivateKey, RSA.ToXmlString(true));
                    File.WriteAllText(pathPublicKey, RSA.ToXmlString(false));

                    MessageBox.Show("Public Key và Private Key đã được lưu lại thành công!");
                }
            }
            catch (CryptographicException ex)
            {
                //Catch this exception in case the encryption did
                //not succeed.
                MessageBox.Show(ex.Message);
            }
        }

        private string pathKeysXML = "";

        private void button2_Click(object sender, EventArgs e)
        {
            //this.textBox5.Clear();
            OpenFileDialog op = new OpenFileDialog();
            op.Filter = "Xml files (*.xml)|*.xml|All Files (*.*)|*.*";
            if (op.ShowDialog() == DialogResult.OK)
            {
                pathKeysXML = op.FileName;
                textBox5.Text = op.FileName;
            }

            if (File.Exists(pathKeysXML))
            {
                if (Path.GetExtension(pathKeysXML) == ".xml")
                {
                    XmlDocument xml = new XmlDocument();
                    xml.LoadXml(File.ReadAllText(pathKeysXML));
                    try
                    {
                        XmlNode xnList = xml.SelectSingleNode("/RSAKeyValue/Modulus");
                        
                        xnList = xml.SelectSingleNode("/RSAKeyValue/Exponent");
                        
                        MessageBox.Show("Load dữ liệu Public Key thành công!");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Failed: " + ex.Message);
                        textBox5.Text = "";
                    }
                }
                else
                {
                    MessageBox.Show("File không đúng định dạng .xml");
                    textBox5.Text = "";
                }
            }
        }

        private bool isEncryptFile = true;
        private void button4_Click(object sender, EventArgs e)
        {
            isEncryptFile = true;
            OpenFileDialog op = new OpenFileDialog();
            op.Filter = "All Files (*.*)|*.*";
            if (op.ShowDialog() == DialogResult.OK)
                textBox6.Text = op.FileName;
        }

        private void button5_Click(object sender, EventArgs e)
        {
            button2.Enabled = false;
            button4.Enabled = false;
            button5.Enabled = false;
            if (textBox5.Text.Length == 0)
            {
                MessageBox.Show("Vui lòng chọn đường dẫn đến Public Key!");
                button2.Enabled = true;
                button4.Enabled = true;
                button5.Enabled = true;
                return;
            }
            if (textBox6.Text.Length == 0)
            {
                MessageBox.Show("Vui lòng chọn đường dẫn đến File cần mã hóa!");
                button2.Enabled = true;
                button4.Enabled = true;
                button5.Enabled = true;
                return;
            }
            MessageBox.Show("Chọn thư mục lưu file mã hóa");
            FolderBrowserDialog f1 = new FolderBrowserDialog();

            if (f1.ShowDialog() == DialogResult.OK)
            {
                tbOutput = f1.SelectedPath;
            }
            else
            {
                button2.Enabled = true;
                button4.Enabled = true;
                button5.Enabled = true;
                return;
            }
 
            btnEncryptDecrypt s = new btnEncryptDecrypt(btnEncryptClick);
            s.BeginInvoke(null, null);

            button2.Enabled = true;
            button4.Enabled = true;
            button5.Enabled = true;         
        }

        public string tbOutput = "";

        private void btnEncryptClick()
        {            
            try
            {
                if (textBox6.Text.Length != 0 &&
               textBox5.Text.Length != 0)
                {
                    string inputFileName = textBox6.Text, outputFileName = "";

                    if (isEncryptFile)
                    {
                        outputFileName = tbOutput + "\\" + Path.GetFileName(textBox6.Text) + ".tt";
                    }
                    //get Keys.
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSA.FromXmlString(File.ReadAllText(this.pathKeysXML));
                    if (isEncryptFile)
                    {
                        RSA_Algorithm(inputFileName, outputFileName, RSA.ExportParameters(false), true);
                        MessageBox.Show("Mã hóa thành công!");
                    }
                    else
                    {
                        string[] filePaths = Directory.GetFiles(inputFileName, "*");

                        if (filePaths.Length == 0 || (filePaths.Length == 1 &&
                            (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                        {
                            MessageBox.Show("Thư mục rỗng!");

                            return;
                        }

                        for (int i = 0; i < filePaths.Length; i++)
                        {
                            outputFileName = tbOutput + "\\" + Path.GetFileName(filePaths[i]);
                            if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                                RSA_Algorithm(filePaths[i], outputFileName + ".tt", RSA.ExportParameters(false), true);
                        }
                    }
                }
                else
                {

                    MessageBox.Show("Dữ liệu không đủ để mã hóa!");
                }
            }
            catch (Exception ex)
            {

                MessageBox.Show("Failed: " + ex.Message);
            }
        }

        private void RSA_Algorithm(string inputFile, string outputFile, RSAParameters RSAKeyInfo, bool isEncrypt)
        {
            try
            {
                FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read); //Đọc file input
                FileStream fsCiperText = new FileStream(outputFile, FileMode.Create, FileAccess.Write); //Tạo file output
                fsCiperText.SetLength(0);
                byte[] bin, encryptedData;
                long rdlen = 0;
                long totlen = fsInput.Length;
                int len;

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.ImportParameters(RSAKeyInfo); // Nhập thông tin khoá RSA 

                int maxBytesCanEncrypted;
                // RSA chỉ có thể mã hóa các khối dữ liệu ngắn hơn độ dài khóa, chia dữ liệu cho một số khối 
                // và sau đó mã hóa từng khối và sau đó hợp nhất chúng
                if (isEncrypt)
                    maxBytesCanEncrypted = ((RSA.KeySize - 384) / 8) + 37;// + 7: OAEP - Đệm mã hóa bất đối xứng tối ưu
                else
                    maxBytesCanEncrypted = (RSA.KeySize / 8);
                // Read from the input file, then encrypt and write to the output file.
                while (rdlen < totlen)
                {
                    if (totlen - rdlen < maxBytesCanEncrypted) maxBytesCanEncrypted = (int)(totlen - rdlen);
                    bin = new byte[maxBytesCanEncrypted];
                    len = fsInput.Read(bin, 0, maxBytesCanEncrypted);

                    if (isEncrypt) encryptedData = RSA.Encrypt(bin, false); // Mã Hoá
                    else encryptedData = RSA.Decrypt(bin, false); // Giải mã

                    fsCiperText.Write(encryptedData, 0, encryptedData.Length);
                    rdlen = rdlen + len;
                }
                fsCiperText.Close(); // Save file
                fsInput.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed: " + ex.Message);
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            button6.Enabled = false;
            button7.Enabled = false;
            button8.Enabled = false;
            if (textBox8.Text.Length == 0)
            {
                MessageBox.Show("Vui lòng chọn đường dẫn đến Private Key!");
                button6.Enabled = true;
                button7.Enabled = true;
                button8.Enabled = true;
                return;
            }
            if (textBox7.Text.Length == 0)
            {
                MessageBox.Show("Vui lòng chọn đường dẫn đến File cần giải mã!");
                button6.Enabled = true;
                button7.Enabled = true;
                button8.Enabled = true;
                return;
            }
            MessageBox.Show("Chọn thư mục lưu file giải mã!");
            FolderBrowserDialog f1 = new FolderBrowserDialog();

            if (f1.ShowDialog() == DialogResult.OK)
            {

                tbOutput = f1.SelectedPath;
            }
            else
            {
                button6.Enabled = true;
                button7.Enabled = true;
                button8.Enabled = true;
                return;
            }

            btnEncryptDecrypt s = new btnEncryptDecrypt(btnDecryptClick);
            s.BeginInvoke(null, null);
            button6.Enabled = true;
            button7.Enabled = true;
            button8.Enabled = true;
        }



        private void btnDecryptClick()
        {
            try
            {
                if (textBox7.Text.Length != 0 &&
                   textBox8.Text.Length != 0
                   )
                {
                    //Calculator time ex...

                    string inputFileName = textBox7.Text, outputFileName = "";

                    if (isEncryptFile && Path.GetExtension(inputFileName) != ".tt")
                    {
                        MessageBox.Show("Tệp tin này không được hỗ trợ đển giải mã!");

                        return;
                    }

                    if (isEncryptFile)
                    {

                        outputFileName = tbOutput + "\\" + Path.GetFileName(inputFileName.Substring(0, inputFileName.Length - 5));
                    }   
                   
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSA.FromXmlString(File.ReadAllText(this.pathKeysXML));

                    if (isEncryptFile)
                    {
                        RSA_Algorithm(inputFileName, outputFileName, RSA.ExportParameters(true), false);
                        MessageBox.Show("Giải mã thành công!");
                    }

                    else
                    {
                        string[] filePaths = Directory.GetFiles(inputFileName, "*.tt", SearchOption.AllDirectories);
                        if (filePaths.Length == 0 || (filePaths.Length == 1 && (Path.GetFileName(filePaths[0]) == "Thumbs.db")))
                        {
                            MessageBox.Show("Thư mục rỗng!");

                            return;
                        }

                        for (int i = 0; i < filePaths.Length; i++)
                            if (Path.GetFileName(filePaths[i]) != "Thumbs.db")
                            {
                                outputFileName = tbOutput + "\\" + Path.GetFileName(filePaths[i].Substring(0, filePaths[i].Length - 5));
                                RSA_Algorithm(filePaths[i], outputFileName, RSA.ExportParameters(true), false);
                            }
                    }
                }
                else
                {
                    MessageBox.Show("Không đủ điều kiện để giải mã!");
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed: " + ex.Message);
            }
        }

        private void button8_Click(object sender, EventArgs e)
        {           
            OpenFileDialog op = new OpenFileDialog();
            op.Filter = "Xml files (*.xml)|*.xml|All Files (*.*)|*.*";
            if (op.ShowDialog() == DialogResult.OK)
            {
                pathKeysXML = op.FileName;
                textBox8.Text = op.FileName;
            }

            if (File.Exists(pathKeysXML))
            {
                if (Path.GetExtension(pathKeysXML) == ".xml")
                {
                    XmlDocument xml = new XmlDocument();
                    xml.LoadXml(File.ReadAllText(pathKeysXML));
                    try
                    {
                        XmlNode xnList = xml.SelectSingleNode("/RSAKeyValue/Modulus");
                        
                        xnList = xml.SelectSingleNode("/RSAKeyValue/Exponent");                     
                        xnList = xml.SelectSingleNode("/RSAKeyValue/D");
                    
                        MessageBox.Show("Load dữ liệu Private Key thành công!");
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Failed: " + ex.Message);
                        textBox8.Text = "";
                    }
                }
                else
                {
                    MessageBox.Show("File không đúng định dạng .xml!");
                    textBox8.Text = "";
                }
            }
        }

        private void button7_Click(object sender, EventArgs e)
        {
            isEncryptFile = true;
            OpenFileDialog op = new OpenFileDialog();
            op.Filter = "All Files (*.*)|*.*";
            if (op.ShowDialog() == DialogResult.OK)
                textBox7.Text = op.FileName;
        }

    private void VigenereRSA_Load(object sender, EventArgs e)
        {

        }

        private void label20_Click(object sender, EventArgs e)
        {

        }

        private void tabPage1_Click(object sender, EventArgs e)
        {

        }

        private void tableLayoutPanel1_Paint(object sender, PaintEventArgs e)
        {

        }

        private void label39_Click(object sender, EventArgs e)
        {

        }

        private void label39_Click_1(object sender, EventArgs e)
        {

        }

        private void label36_Click(object sender, EventArgs e)
        {

        }

        private void label31_Click(object sender, EventArgs e)
        {

        }

        private void Gorillas_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void textBox3_TextChanged(object sender, EventArgs e)
        {

        }

        private void groupBox2_Enter(object sender, EventArgs e)
        {

        }

        private void groupBox3_Enter(object sender, EventArgs e)
        {

        }

        private void label21_Click(object sender, EventArgs e)
        {

        }
    }

}
