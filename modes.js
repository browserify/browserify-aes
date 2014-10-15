exports['aes-128-ecb'] = {
  cipher: 'AES',
  key: 128,
  iv: 0,
  mode: 'ECB'
};
exports['aes-192-ecb'] = {
  cipher: 'AES',
  key: 192,
  iv: 0,
  mode: 'ECB'
};
exports['aes-256-ecb'] = {
  cipher: 'AES',
  key: 256,
  iv: 0,
  mode: 'ECB'
};
exports['aes-128-cbc'] = {
  cipher: 'AES',
  key: 128,
  iv: 16,
  mode: 'CBC'
};
exports['aes-192-cbc'] = {
  cipher: 'AES',
  key: 192,
  iv: 16,
  mode: 'CBC'
};
exports['aes-256-cbc'] = {
  cipher: 'AES',
  key: 256,
  iv: 16,
  mode: 'CBC'
};
exports['aes128'] = exports['aes-128-cbc'];
exports['aes192'] = exports['aes-192-cbc'];
exports['aes256'] = exports['aes-256-cbc'];