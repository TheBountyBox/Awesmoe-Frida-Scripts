//Run # frida -U -f com.fss.indus -l indusind-bypass.js --no-pause


function SSLPinningBypass(){
	var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
 
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                //console.log("[+] (Android 7+) TrustManagerImpl verifyChain() called. Not throwing an exception.");
                return untrustedChain;
            }

            PinningTrustManager.checkServerTrusted.implementation = function() {
                //console.log("[+] Appcelerator checkServerTrusted() called. Not throwing an exception.");
            }
        } catch (err) {
			//console.log("[-] TrustManagerImpl Not Found");
        }

        //console.log("[.] TrustManager Android < 7 detection...");
        var TrustManager = Java.registerClass({
            name: 'com.sensepost.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

        try {
            // Override the init method, specifying our new TrustManager
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.warn("[+] Bypassed SSLPinning with custom TrustManager android < 7");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch (err) {
            //console.log("[-] TrustManager Not Found");
        }      
	
	
}


setTimeout(function() {
	Java.perform(function() {
		
	
		var N_CertReader = Java.use("com.konylabs.ffi.N_CertReader");
		N_CertReader["execute"].overloads[0].implementation = function() {
			var retval = this["execute"].apply(this, arguments);
			if ( arguments[0] == 5 || arguments[0] == 4){
				var retval = [Java.use("java.lang.Boolean").$new(false), Java.use("java.lang.Double").$new("0.0d")]
				console.warn("[+] Bypassed proxyCheck() and isUsbConnected()");
			} else if(arguments[0] == 3){
				
				var KonyMain = Java.use("com.konylabs.android.KonyMain").$new()
				var AppSignatureHelper = Java.use("kony.com.certreader.AppSignatureHelper").$new(KonyMain.getAppContext()).getAppSignatures()
				var sig1 = Java.use("java.util.ArrayList").$new(AppSignatureHelper).toString().replace("[","").replace("]","")
			
				var Vectorlist = Java.use('java.util.Vector');
				var items = Vectorlist.$new();
				items.add(sig1);
				 var retval = [items, Java.use("java.lang.Double").$new("0.0d")]
				//console.log("[++++] getAppSignatures with Values  -> " + retval);
			}
			return retval;
		}
		
		
		var RootDetector = Java.use("kony.com.rootdetector.RootDetector");
		RootDetector["isRooted"].overloads[0].implementation = function() {
			console.warn("[+] Bypassed Root Detection");
			return false;
		}
		
		SSLPinningBypass();
        
	  }//end of main function
	); // End Java.perform   
}, 0);


