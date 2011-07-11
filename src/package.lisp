(defpackage #:cl-openid
  (:use #:common-lisp
        #:drakma
        #:puri
        #:net.html.parser
        #:split-sequence
        #:cl-base64
        #:trivial-utf-8
        #:ironclad
        #:bordeaux-threads)
  (:shadowing-import-from :cl #:null) ; Ironclad shadows NULL, we don't want to  
  (:export 
   ;; --- RP ---
   ;; RP class
   #:relying-party #:realm #:root-uri   
   ;; RP API
   #:initiate-authentication #:+authproc-handle-parameter+ #:handle-indirect-response 
   ;; AUTH-PROCESS structure	   
   #:auth-process #:auth-process-p #:protocol-version-major #:protocol-version-minor 
   #:protocol-version #:claimed-id #:op-local-id #:return-to #:xrds-location 
   #:provider-endpoint-uri #:timestamp   
   ;; assertion error condition
   #:openid-assertion-error #:code #:reason #:authproc #:message
   ;; --- OP ---
   ;; OP class
   #:openid-provider #:endpoint-uri  
   ;; OP API
   #:handle-openid-provider-request #:handle-checkid-setup #:handle-checkid-immediate
   ;; OP responses
   #:successful-response-uri #:cancel-response-uri #:+indirect-response-code+
   ;; Message API
   #:in-ns #:message-field #:message-v2-p #:make-message #:copy-message #:auth-request-realm 
   ))
