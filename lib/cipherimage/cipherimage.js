/*
 *  CipherImage JS Library, copyright (c) 2021 Greg Sidal, inherits CryptoJS licence
 *    requires {cryptojs}/rollups/aes.js (for BinaryCrypto class)
 *
 *  Encrypts/decrypts image data (rasters) with AES 256, opens from PNG files, displays on canvas
 *
 *    Create:      var ci = new CipherImage.FileViewer( canvas, notify_callback );
 *    Open image:  ci.setsrc( filename );
 *    Detect:      ci.isCipherimg();
 *    Encrypt:     ci.encrypt( pass );
 *    Decrypt:     if (!ci.decrypt( pass )) alert( "Wrong key!" );
 *    Save PNG:    <a href="" onclick="this.href=ci.getBmpDataUrl()" download="cipherimage.png">Save</a>
 * 
 *  CipherImage raster: Prefix + IV + Salt + CipherText
 *    A row padded with random pixels is added to make room for all prefix data
 *    'Prefix' (constant) is used for CipherImage recognition
 *
 *  'CipherText' when decrypted: PrefixPixel + Image raster
 *    'PrefixPixel' is added to simplify PlainText recognition (correct password used to decrypt)
 */


CipherImage_Prefix = "CrIm";
CipherImage = {
  prefix: CipherImage_Prefix,
  prefixarr: [CipherImage_Prefix.charCodeAt(0), CipherImage_Prefix.charCodeAt(1),
              CipherImage_Prefix.charCodeAt(2), 255, CipherImage_Prefix.charCodeAt(3)]
};


/*
 *  image file crypto on canvas
 */
CipherImage.FileViewer = function( canv, callback ) {
  this.encrypt = function( pass ) {
    var data = this.ifc.getdata();
    var cipherimage = CipherImage.Data.encrypt( pass, data, CipherImage.prefix, CipherImage.prefixarr );
    if (cipherimage)
      this.ifc.setdata( cipherimage );
  }
  this.decrypt = function( pass, ignorepixtest ) {
    var data = this.ifc.getdata();
    var plainimage = CipherImage.Data.decrypt( pass, data, CipherImage.prefix, CipherImage.prefixarr );
    if (plainimage)
      this.ifc.setdata( plainimage );
    return plainimage;
  }
  this.decryptreset = function( pass, plainimg ) {
    var plain = CipherImage.Data.decryptret( pass, plainimg, CipherImage.prefix, CipherImage.prefixarr );
    if (plain.imagedata)
      this.ifc.setdata( plain.imagedata );
    return plain.isplain;
  }
  this.testpass = function( pass ) {
    var data = this.ifc.getdata();
    return CipherImage.Data.testpass( pass, data, CipherImage.prefix, CipherImage.prefixarr );
  }
  this.setsrc = function( f, u ) {
    return this.ifc.setsrc( f, u );
  }
  this.getviewdata = function() {
    return this.ifc.getviewdata();
  }
  this.getrgbdata = function() {
    return CipherImage.Data.imgdata2rgb( this.ifc.getdata() );
  }
  this.getBmpDataUrl = function() {
    return this.ifc.getBmpDataUrl();
  }
  this.isCipherimg = function() {
    var d = this.ifc.getdata();
    return d ? CipherImage.Data.iscipherimg( d, CipherImage.prefixarr ) : false;
  }
  this.save2file = function( f ) {
    return this.ifc.save2file( f );
  }
  this.ifc = new ImageViewer.File( canv, callback );
  this.callback = callback;
}


/*
 *  ImageData crypto
 */
CipherImage.Data = {
  /* unpack [rgbrgbrgb...] array into imgdata */
  rgb2imgdata: function( rgb, w, h ) {
    var idobj = new ImageData( w, h );
    if (!rgb)
      return idobj;
    var imgdata = idobj.data;
    var imgdatalen = imgdata.length;
    var rgblen = rgb.length;
    for( var i=0,j=0; j<rgblen && i<imgdatalen; i+=4,j+=3 )
      imgdata[i] = rgb[j], imgdata[i+1] = rgb[j+1], imgdata[i+2] = rgb[j+2], imgdata[i+3] = 255;
    return idobj;
  },
  /* pack imgdata into [rgbrgbrgb...] array */
  imgdata2rgb: function( idobj ) {
    var imgdata = idobj.data;
    var imgdatalen = imgdata.length;
    var binarr = new Uint8Array( (imgdatalen/4) * 3);
    for( var i=0,j=0; i<imgdatalen; i+=4,j+=3 )
      binarr[j] = imgdata[i], binarr[j+1] = imgdata[i+1], binarr[j+2] = imgdata[i+2];
    return binarr;
  },
  /* pack ImageData into binary string */
  imgdata2binstr: function( idobj, prepix ) {
    var binstr = prepix ? String.fromCharCode(prepix[0],prepix[1],prepix[2]) : "";
    var imgdata = idobj.data;
    var imgdatalen = imgdata.length;
    for( var i=0; i<imgdatalen; i+=4 )
      binstr += String.fromCharCode( imgdata[i], imgdata[i+1], imgdata[i+2] );
    return binstr;
  },
  /* test decrypted first pixel to validate pass */
  testprepix: function( binstr, prepix ) {
    var pp = [binstr.charCodeAt(0), binstr.charCodeAt(1), binstr.charCodeAt(2)];
    return (prepix[0] == pp[0]) && (prepix[1] == pp[1]) && (prepix[2] == pp[2]);
  },
  /* unpack rgbrgbrgb... string into ImageData */
  binstr2imgdata: function( binstr, w, h, prepix ) {
    var j = 0;
    if (prepix) {
      if (!CipherImage.Data.testprepix( binstr, prepix ))
        return null;
      j = 3;
    }
    var idobj = new ImageData( w, h );
    if (!binstr)
      return idobj;
    var imgdata = idobj.data;
    var imgdatalen = imgdata.length;
    var binstrlen = binstr.length;
    for( var i=0; j<binstrlen && i<imgdatalen; i+=4,j+=3 ) {
      imgdata[i] = binstr.charCodeAt( j );
      imgdata[i+1] = binstr.charCodeAt( j+1 );
      imgdata[i+2] = binstr.charCodeAt( j+2 );
      imgdata[i+3] = 255;
    }
    for( ; i<imgdatalen; i+=4 )
      imgdata[i]=Rand.range(0,255), imgdata[i+1]=Rand.range(0,255), imgdata[i+2]=Rand.range(0,255), imgdata[i+3]=255;
    return idobj;
  },
  /* compare piece of image */
  compare: function( idobj, rgbarr, offset ) {
    offset = offset ? offset : 0;
    var imgdata = idobj.data;
    var len = imgdata.length;
    for( var i=offset,j=0; i<len && j<rgbarr.length; i++,j++ )
      if (imgdata[i] != rgbarr[j])
        return false;
    return true;
  },
  /*  */
  iscipherimg: function( imgdata, prefixarr ) {
    return CipherImage.Data.compare( imgdata, prefixarr );
  },
  /* unpack ImageData into cipherstr */
  imgdata2cipherstr: function( imgdata, maxlen ) {
    return CipherImage.Data.imgdata2binstr( imgdata );
  },
  /* pack cipherstr into ImageData */
  cipherstr2imgdata: function( cipherstr, w, h ) {
    return CipherImage.Data.binstr2imgdata( cipherstr, w, h+1 );
  },
  /* encrypt ImageData buffer, return new ImageData */
  encrypt: function( pass, imgdata, prefix, prepix ) {
    var binstr = CipherImage.Data.imgdata2binstr( imgdata, prepix );
    var cipherstr = BinaryCrypto.encrypt( pass, binstr, prefix );
    return CipherImage.Data.cipherstr2imgdata( cipherstr, imgdata.width, imgdata.height );
  },
  /* decrypt ImageData buffer */
  decrypt: function( pass, imgdata, prefix, prepix ) {
    var cipherstr = CipherImage.Data.imgdata2cipherstr( imgdata );
    var plainstr = BinaryCrypto.decrypt( pass, cipherstr, prefix );
    return CipherImage.Data.binstr2imgdata( plainstr, imgdata.width, imgdata.height-1, prepix );
  },
  /* decrypt ImageData buffer, return imgdata even if it fails prepix test */
  decryptret: function( pass, imgdata, prefix, prepix ) {
    var cipherstr = CipherImage.Data.imgdata2cipherstr( imgdata );
    var plainstr = BinaryCrypto.decrypt( pass, cipherstr, prefix );
    var im = CipherImage.Data.binstr2imgdata( plainstr, imgdata.width, imgdata.height-1 );
    return {imagedata:im,isplain:CipherImage.Data.testprepix(plainstr,prepix)};
  },
  /* decrypt part of ImageData buffer to test if pass correct */
  testpass: function( pass, imgdata, prefix, prepix ) {
    var cipherstr = BinaryCrypto.arr2str( imgdata.data, 
                        BinaryCrypto.hdrlength(prefix)+(BinaryCrypto.blklength()*2) );
    var plainstr = BinaryCrypto.decrypt( pass, cipherstr, prefix );
    return CipherImage.Data.testprepix( plainstr, prepix );
  }
};


ImageViewer = {};
/*
 *  image data on canvas
 */
ImageViewer.Data = function( canv ) {
  this.drawimg = function() {
    if (!this.src.data) {
      this.view.context.fillStyle = 'rgb(255,255,255)';
      this.view.context.fillRect( 0, 0, this.view.canvas.width, this.view.canvas.height );
      return false;
    }
    this.view.canvas.width = this.src.data.width, this.view.canvas.height = this.src.data.height;
    this.view.context.putImageData( this.src.data, 0, 0 );
    return true;
  }
  this.setdata = function( data ) {
    this.src.data = data;
    return this.drawimg();
  }
  this.setimgdata = function( img ) {
    this.view.canvas.width = img.width, this.view.canvas.height = img.height;
    this.view.context.drawImage( img, 0, 0 );
    this.src.data = this.getviewdata();
  }
  this.getdata = function() {
    return this.src.data;
  }
  this.getcanvas = function() {
    return this.view.canvas;
  }
  this.getviewdata = function() {
    return this.view.context.getImageData( 0, 0, this.view.canvas.width, this.view.canvas.height );
  }
  this.view = {canvas:canv,context:canv.getContext('2d')};
  this.src = {data:null/*,prevdata:null*/};
}


/*
 *  image file on canvas
 */
ImageViewer.File = function( canv, callback ) {
  this.setdata = function( data ) {
    return this.idc.setdata( data );
  }
  this.getdata = function() {
    return this.idc.getdata();
  }
  this.getviewdata = function() {
    return this.idc.getviewdata();
  }
  this.drawimg = function() {
    return this.idc.drawimg();
  }
  this.setimgdata = function( img ) {
    this.idc.setimgdata( img );
  }
  this.loadfiledata = function() {
    var this_ = this;
    var callbacks = {
      onloaded: function(d) {this_.loadinprogress=false; this_.setimgdata(d); this_.onnotify();},
      onloaderror: function(m) {this_.loadinprogress=false; this_.onnotify(m);},
      onloadnotify: function(m) {this_.onnotify(m);}
    }
    this.loadinprogress = true;
    if (this.src.file)
      FileHandler.loadimgfile( callbacks, this.src.file );
    else
      FileHandler.loadimgurl( callbacks, this.src.url );
  }
  this.save2file = function( f ) {
  }
  this.onnotify = function( msg ) {
    if (this.callback)
      this.callback( msg );
  }
  this.getmetadata = function() {
    return this.metadata;
  }
  this.setmetadata = function( part, md ) {
    if (part)
      this.metadata[part] = md;
  }
  this.setsrc = function( f, u ) {
    this.src.file = f;
    this.src.url = u;
    return this.loadfiledata();
  }
  this.getBmpDataUrl = function() {
    return this.idc.getcanvas().toDataURL( 'image/png', 1.0 );
  }
  this.idc = new ImageViewer.Data( canv );
  this.src = {file:null, url:null};
  this.callback = callback;
  this.metadata = {};
}


/*
 *  binary data crypto package
 */
var BinaryCrypto = {
  /* return length of blocks in ciphers */
  blklength: function() {
    return 16;
  },
  /* return length of header that is prepended to ciphers */
  hdrlength: function( prefix ) {
    return prefix.length + 16 + 8;
  },
  /* take byte array, return byte string */
  arr2str: function( arr, maxlen ) {
    var str = "";
    var arrlen = maxlen ? (maxlen<arr.length?maxlen:arr.length): arr.length;
    for( var i=0; i<arrlen; i++ )
      str += String.fromCharCode( arr[i] );
    return str;
  },
  /* take byte string, return byte array */
  str2arr: function( str ) {
    var arr = new Uint8Array();
    var strlen = str.length;
    for( var i=0; i<strlen; i++ ) 
      arr[i] = str.charCodeAt( i );
    return arr;
  },
  /* take plainy as byte string, return "prefix+iv+salt+ciphertext" as byte string */
  encrypt: function( pass, plainstr, prefix ) {
    var plain = CryptoJS.enc.Latin1.parse( plainstr );
    var cipher = CryptoJS.AES.encrypt( plain, pass );
    var cipherstr = prefix ? prefix : "";
    cipherstr += cipher.iv.toString( CryptoJS.enc.Latin1 );
    cipherstr += cipher.salt.toString( CryptoJS.enc.Latin1 );
    return cipherstr + cipher.ciphertext.toString( CryptoJS.enc.Latin1 );
  },
  /* parse cipherstr into CipherParams */
  parsecipherstr: function( cipherstr, prefix ) {
    var prelen = prefix ? prefix.length : 0;
    var ct = cipherstr.slice(24+prelen);
    //alert( ct.length );
    ct = CryptoJS.enc.Latin1.parse( cipherstr.slice(24+prelen) );
    var c = CryptoJS.lib.CipherParams.create( {ciphertext:ct} );
    c.iv = CryptoJS.enc.Latin1.parse( cipherstr.slice(prelen,16+prelen) );
    c.salt = CryptoJS.enc.Latin1.parse( cipherstr.slice(16+prelen,24+prelen) );
    return c;
  },
  /* take "prefix+iv+salt+ciphertext" as byte string, return plainy as byte string */
  decrypt: function( pass, cipherstr, prefix ) {
    var c = BinaryCrypto.parsecipherstr( cipherstr, prefix );
    var plain = CryptoJS.AES.decrypt( c, pass ); //, {format:{parse:BinaryCrypto.parsecipherstr}}
    var plainstr = plain.toString( CryptoJS.enc.Latin1 );
    return plainstr;
  }
};


/*
 *  file handler
 */
var FileHandler = {
  /* Fetch image file from local drive */
  loadimgfile: function( callbacks, file ) {
    var reader = new FileReader();
    reader.onerror = function( e ) {callbacks.onloaderror('ERROR: file read failed');}
    reader.onload = function( e ) {
      var img = new Image();
      img.onload = function() {callbacks.onloadnotify(file.name); callbacks.onloaded(img);}
      img.onerror = function() {callbacks.onloaderror('ERROR: '+file.name+' not a supported image file type');}
      img.src = e.target.result;
    }
    reader.readAsDataURL( file );
  },
  /* Fetch image file from web */
  loadimgurl: function( callbacks, url ) {
    function err( m ) {callbacks.onloaderror(m);}
    function notify( m ) {
      if (m.slice(0,5) != 'data:')
        callbacks.onloadnotify( m );
    }
    var img = new Image();
    img.onerror = function() {callbacks.onloaderror('ERROR: '+file.name+' could not be loaded, or not a supported image file type');}
    img.onload = function() {
      notify( url );
      callbacks.onloaded( img );
    }
    try {
      img.src = url;
    }
    catch( e ) {
      err( "ERROR: " + url );
    }
  },
  /* Fetch binary file from web */
  loadurlbinary: function( callbacks, url ) {
    function progress( e ) {
      callbacks.onloadnotify( url + !e.lengthComputable || e.loaded==e.total ?
                                    '' : ' (loading '+((e.loaded*100)/e.total)+'%)' );
    }
    function complete( e ) {
      callbacks.onloadnotify( url );
      callbacks.onloaded(new Uint8Array(this.response));
    }
    function err( m ) {callbacks.onloaderror(m);}
    function failed() {err(this.status==404 ? "URL not found" : "Server busy");}
    function canceled( e ) {err( "Canceled" );}
    callbacks.onloadnotify( url );
    try {
      var req = new XMLHttpRequest();
      req.addEventListener( "progress", progress, false );
      req.addEventListener( "load", complete, false );
      req.addEventListener( "error", failed, false );
      req.addEventListener( "abort", canceled, false );
      req.open( "GET", url, true );
      req.responseType = "arraybuffer";
      req.send();
    }
    catch( e ) {
      err( "ERROR: " + url );
    }
  }
}


/*
 *  random vals and infinite integers (expanding byte array integers)
 */
var Rand = {
  r: function( ) {
    var r = 0;
    if (window.crypto && window.crypto.getRandomValues) {
      var array = new Uint32Array( 2 );
      window.crypto.getRandomValues( array );
      array[1] = 0xffffffff;
      r = array[0] / array[1];
    }
    else
      r = Math.random();
    return r;
  },
  range: function( min, max ) {
    var r = Rand.r();
    return min + Math.round( r * (max-min) );
  },
  bytearray: function( len ) {
    var ra = new Uint8Array( len );
    for( var i=0; i<len; i++ )
      ra[i] = Rand.range( 0, 255 );
    return ra;
  },
  bytes2hexstr: function( ra ) {
    var hex = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    var str = "", tmp=0;
    for( var i=0; i<ra.length; i++ )
      str += hex[Math.floor(ra[i]/16)] + hex[ra[i]%16];
    return str;
  },
  initbytes: function( len ) {
    var b = [];
    for( var i=0; i<len; i++ )
      b[i] = 0;
    return b;
  },
  incbytes: function( b ) {
    var len = b.length;
    for( var i=len-1; i>=0; i-- ) {
      b[i]++;
      if (b[i] < 256)
        break;
      b[i] = 0;
    }
    if (i < 0)
      b[len] = 0;
    return b;
  }
};
