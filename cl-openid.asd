; -*- lisp -*-

(defpackage #:cl-openid.system
  (:use #:common-lisp #:asdf))
(in-package #:cl-openid.system)

(defsystem #:cl-openid
  :name "cl-openid"
  :description "cl-openid"
  :version "0.1"
  :author "Maciej Pasternacki"
  :maintainer "Maciej Pasternacki"
  :licence "LLGPL, see http://opensource.franz.com/preamble.html for details"

  :components
  ((:module #:src
            :components ((:file "package"))))
  :depends-on (#:hunchentoot #:drakma #:ironclad))

(defsystem #:cl-openid.test
  :version "0.1"
  :description "Test suite for cl-openid"
  :components
  ((:module #:t
    :components ((:file "suite"))))
  :depends-on (#:cl-openid #:fiveam))

(defmethod perform ((op asdf:test-op)
                    (system (eql (find-system :cl-openid))))
  "Perform unit tests for cl-openid"
  (asdf:operate 'asdf:load-op :cl-openid.test)
  (funcall (intern (string :run!) (string :it.bese.fiveam))
           (intern (string :cl-openid) (string :cl-openid))))
