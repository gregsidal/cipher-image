# cipher-image
JS library for image encryption


<br/>

Encrypts/decrypts image data (rasters) with AES 256, opens from PNG files, displays on canvas

<br/>
Two JS files needed: 

    lib/cipherimage/cipherimages.js
    lib/cryptojs/rollups/aes.js
    
<br/>
High-level calls (results show on canvas automatically):

    Create:      var ci = new CipherImage.FileViewer( canvas, notify_callback );
    Open image:  ci.setsrc( filename );
    Detect:      ci.isCipherimg();
    Encrypt:     ci.encrypt( pass );
    Decrypt:     if (!ci.decrypt( pass )) alert( "Wrong key!" );
    Save PNG:    <a href="" onclick="this.href=ci.getBmpDataUrl()" download="cipherimage.png">Save</a>

<br/>
Browser programs that use this library:

    Cipher-image encrypt/decrypt utility
    Cipher-image miner (brute-force a cipher-image)

<br/>
Both programs are live at:
 
https://gregsidal.github.io <br/>
https://gregsidal.neocities.org (mirror)
    

<br/>
2021 Greg Sidal, inherits CryptoJS licence
