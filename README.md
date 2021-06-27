# cipher-image
JS library for image encryption
Copyright (c) 2021 Greg Sidal, inherits CryptoJS licence

lib/cipherimage/cipherimages.js (requires lib/cryptojs/rollups/aes.js)

Encrypts/decrypts image data (rasters) with AES 256, opens from PNG files, displays on canvas

    Create:      var ci = new CipherImage.FileViewer( canvas, notify_callback );
    Open image:  ci.setsrc( filename );
    Detect:      ci.isCipherimg();
    Encrypt:     ci.encrypt( pass );
    Decrypt:     if (!ci.decrypt( pass )) alert( "Wrong key!" );
    Save PNG:    <a href="" onclick="this.href=ci.getBmpDataUrl()" download="cipherimage.png">Save</a>

Browser programs that use this library:

    Cipher-image encrypt/decrypt utility
    Cipher-image miner
    
Both programs are live at:

    https://gregsidal.github.io
    https://gregsidal.neocities.org (mirror)
