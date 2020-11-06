const [,, command, password, value] = process.argv;
const { Password } = require('./');

if (command === 'encrypt') {
  const pass = new Password(password);
  pass.encrypt(Buffer.from(value, 'utf8'))
    .then(buffer => {
      console.log(buffer.toString('hex'));
    })
    .catch(err => {
      console.error(err);
      process.exit(1);
    });
} else if (command === 'decrypt') {
  const pass = new Password(password);
  pass.decrypt(Buffer.from(value, 'hex'))
    .then(buffer => {
      console.log(buffer.toString('utf8'));
    })
    .catch(err => {
      console.error(err);
      process.exit(1);
    });
} else {
  console.error(`Unknown command ${command}. Expected encrypt or decrypt`);
}