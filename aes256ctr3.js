var crypto = require('crypto'),
  password = '1234567890abcdef1234567890abcdef',
  iv = '1234567890abcdef',
  text = "pereira";

function encrypt(iv, text, password){
  var cipher = crypto.createCipheriv('aes-256-ctr', password, iv)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}

function decrypt(iv, text, password){
  var decipher = crypto.createDecipheriv('aes-256-ctr', password, iv)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}
var encrypted_data = encrypt(iv, text, password);
var decrypted_data = decrypt(iv,encrypted_data,password);
console.log('encrypted_data',encrypted_data);
console.log('decrypted_data',decrypted_data);
