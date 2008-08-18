                                   CL-OpenID
                                   =========

Author: Maciej Pasternacki <maciej@pasternacki.net>
Date: 2008/08/18 19:47:17


Cl-OpenID is an implementation of [OpenID] protocol in Common Lisp.  It
implements [OpenID Authentication 2.0] standard and is compatible with
[OpenID Authentication 1.1].  Both Relying Party (formerly called OpenID
Consumer), and OpenID Provider are implemented.

CL-OpenID is available on terms of [GNU Lesser General Public License version 2.1] with Franz Inc.'s [preamble], also known as LLGPL (Lisp
Lesser General Public License).

The project is developed as a [Google Summer of Code 2008] project,
developed by Maciej Pasternacki and mentored by Anton Vodonosov.
Original application is published at
[http://trac.common-lisp.net/cl-openid/wiki/OriginalProposal].

Table of Contents
=================
1 Contact
2 Downloading
    2.1 Dependencies
        2.1.1 CL-Librarian shelf
    2.2 Example code
3 Provided API
    3.1 Relying Party
        3.1.1 Class =RELYING-PARTY=
            3.1.1.1 Accessor =ROOT-URI= /relying-party/ ⇒ /uri/
            3.1.1.2 Accessor =REALM= /relying-party/ ⇒ /uri/
        3.1.2 Constant =+AUTHPROC-HANDLE-PARAMETER+=
        3.1.3 Function =INITIATE-AUTHENTICATION= /relying-party given-id &key immediate-p/ ⇒ /uri/
        3.1.4 Function =HANDLE-INDIRECT-RESPONSE= /relying-party message request-uri &optional auth-process/ ⇒ /authendicated-id auth-process/
        3.1.5 Condition =OPENID-ASSERTION-ERROR=
            3.1.5.1 Accessor =CODE= /openid-assertion-error/ ⇒ /keyword/
            3.1.5.2 Accessor =REASON= /openid-assertion-error/ ⇒ /string/
            3.1.5.3 Accessor =AUTHPROC= /openid-assertion-error/ ⇒ /auth-process/
            3.1.5.4 Accessor =MESSAGE= /openid-assertion-error/ ⇒ /message/
        3.1.6 Structure =AUTH-PROCESS=
            3.1.6.1 Function =AUTH-PROCESS-P= /object/ ⇒ /boolean/
            3.1.6.2 Accessor =PROTOCOL-VERSION-MAJOR= /auth-process/ ⇒ /integer/
            3.1.6.3 Accessor =PROTOCOL-VERSION-MINOR= /auth-process/ ⇒ /integer/
            3.1.6.4 Accessor =PROTOCOL-VERSION= /auth-process/ ⇒ /cons/
            3.1.6.5 Accessor =CLAIMED-ID= /auth-process/ ⇒ /uri/
            3.1.6.6 Accessor =OP-LOCAL-ID= /auth-process/ ⇒ /uri/
            3.1.6.7 Accessor =ENDPOINT-URI= /auth-process/ ⇒ /uri/
            3.1.6.8 Accessor =RETURN-TO= /auth-process/ ⇒ /uri/
            3.1.6.9 Accessor =TIMESTAMP= /auth-process/ ⇒ /universal-time/
            3.1.6.10 Accessor =XRDS-LOCATION= /auth-process/ ⇒ /uri/
    3.2 OpenID Provider
        3.2.1 Class =OPENID-PROVIDER=
            3.2.1.1 Accessor =OP-ENDPOINT-URI= /op/ ⇒ /uri/
        3.2.2 Constant =+INDIRECT-RESPONSE-CODE+=
        3.2.3 Function =HANDLE-OPENID-PROVIDER-REQUEST= /op message &key secure-p/ ⇒ /response values/
        3.2.4 Function =CANCEL-RESPONSE= /op/ /message/ ⇒ /response values/
        3.2.5 Function =SUCCESSFUL-RESPONSE= /op/ /message/ ⇒ /response values/
        3.2.6 Macro =WITH-INDIRECT-ERROR-HANDLER= /&body body/ ⇒ /response values/
        3.2.7 Function =SIGNAL-INDIRECT-ERROR= /message reason &rest reason-args/
        3.2.8 Generic =HANDLE-CHECKID-IMMEDIATE= /op message/ ⇒ /generalized-boolean/
        3.2.9 Generic =USER-SETUP-URL= /op message/ ⇒ /uri/
        3.2.10 Generic =HANDLE-CHECKID-SETUP= /op message/ ⇒ /response values/
        3.2.11 Protocol messages
            3.2.11.1 Function =MAKE-MESSAGE= /&rest parameters/ ⇒ /message/
            3.2.11.2 Function =COPY-MESSAGE= /message &rest parameters/ ⇒ /message/
            3.2.11.3 Function =IN-NS= /message &optional namespace/ ⇒ /message/
            3.2.11.4 Function =MESSAGE-FIELD= /message field-name/ ⇒ /value/
            3.2.11.5 Function =MESSAGE-V2-P= /message/ ⇒ /boolean/


1 Contact
#########
  Discussions regarding development are conducted on [cl-openid-devel]
  mailing list.  This is the best place to bring up questions,
  suggestions or to discuss issues connected with CL-OpenID.

  Important announcements are posted to [cl-openid-announce] mailing
  list.  This is a low-volume, announcement-only list.  All the
  announcements are also posted on development list.

  Bugs are tracked on [project's Trac bugtracker].  Interface for
  submitting new tickets is available at
  [http://trac.common-lisp.net/cl-openid/newticket].  All ticket change
  notifications are sent to [cl-openid-ticket] mailing list.

  Miscellaneous information on project, of various quality and
  relevance, can be found on project's [Trac wiki].

2 Downloading
#############
  Project Web page is [http://common-lisp.net/project/cl-openid/].  Most
  recent version of the code can be downloaded with [darcs]:

   darcs get http://common-lisp.net/project/cl-openid/

2.1 Dependencies
^^^^^^^^^^^^^^^^
   Project depends on following libraries:
   - [drakma],
   - [ironclad],
   - [xmls],
   - [split-sequence],
   - [cl-base64],
   - [trivial-utf-8],
   - [bordeaux-threads]
   - [puri],
   - [cl-html-parse] (on implementations other than Allegro CL).

   Example code depends also on [Hunchentoot].  Unit tests depend on
   [FiveAM] testing framework.

   All required libraries should be ASDF-installable, so running =darcs
   dist= and then calling =ASDF-INSTALL:INSTALL= on resulting tarball
   should provide complete dependencies.

2.1.1 CL-Librarian shelf
~~~~~~~~~~~~~~~~~~~~~~~~
    As an alternative to ASDF-Install, a [CL-Librarian] shelf definition
    for dependencies is provided.  To use it, run following shell
    commands in CL-OpenID directory:
     darcs get http://www.pasternacki.net/repos/cl-librarian/ lib
     cd lib
     sh bootstrap.sh
     cd ..
    Then start your favourite Lisp implementation and call:
     (load "shelf")
     (cl-librarian:download-shelf 'cl-openid.deps) ; for the first time or when new dependency is added
     (cl-librarian:use-shelf 'cl-openid.deps) ; when libraries are already downloaded
     (asdf:oos 'asdf:load-op :cl-openid)
     (asdf:oos 'asdf:test-op :cl-openid) ; run 5am unit tests

2.2 Example code
^^^^^^^^^^^^^^^^
   Example implementation of Relying Party and OpenID Provider for
   [Hunchentoot] web server is included in =examples/= subdirectory.  For
   convenience, both examples can be loaded as =CL-OPENID.EXAMPLES=
   ASDF system:
    (asdf:oos 'asdf:load-op :cl-openid.examples)

3 Provided API
##############

3.1 Relying Party
^^^^^^^^^^^^^^^^^

3.1.1 Class =RELYING-PARTY=
~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Relying Party class.

3.1.1.1 Accessor =ROOT-URI= /relying-party/ ⇒ /uri/
===================================================
     Root URI address of the Relying Party instance.

     Used to generate return_to redirections.

3.1.1.2 Accessor =REALM= /relying-party/ ⇒ /uri/
================================================
     Relying Party realm.

3.1.2 Constant =+AUTHPROC-HANDLE-PARAMETER+=
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Name of HTTP GET parameter, sent in return_to URI, which contains
    AUTH-PROCESS object unique handle.

3.1.3 Function =INITIATE-AUTHENTICATION= /relying-party given-id &key immediate-p/ ⇒ /uri/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Initiate authentication process by /relying-party/ for identifier
    /given-id/ received from user.

    If /immediate-p/ is true, initiates immediate authentication
    process.  Returns URI to redirect user to.

3.1.4 Function =HANDLE-INDIRECT-RESPONSE= /relying-party message request-uri &optional auth-process/ ⇒ /authendicated-id auth-process/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handle indirect response /message/ for /relying-party/, coming at /request-uri/, concerning /authproc/.

    /authproc/ can be a literal AUTH-PROCESS object, or a string
    (unique authproc handle, sent earlier by Relying Party). When
    /authproc/ is NIL or not supplied, its handle is taken from
    /message/ field named =+AUTHPROC-HANDLE-PARAMETER+=.

    Returns claimed ID URI on success, NIL on failure.  As second
    value, always returns AUTH-PROCESS object.

3.1.5 Condition =OPENID-ASSERTION-ERROR=
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Error signaled by Relying Party when indirect response cannot be
    verified correctly.

3.1.5.1 Accessor =CODE= /openid-assertion-error/ ⇒ /keyword/
============================================================
     Keyword code of error.

     Possible values are
     - =:SERVER-ERROR= (received response is an erroor message),
     - =:SETUP-NEEDED= (negative response to immediate request),
     - =:INVALID-RETURN-TO= (request doesn't match previously sent openid.return_to),
     - =:INVALID-NAMESPACE= (invalid openid.ns in received message),
     - =:INVALID-ENDPOINT= (endpoint specified in assertion does not match previously discovered information),
     - =:INVALID-CLAIMED-ID= (received claimed_id differs from specified previously, discovery for received claimed ID returns other endpoint),
     - =:INVALID-NONCE= (repeated openid.nonce),
     - =:INVALID-SIGNATURE= (signature verification failed),
     - =:INVALID-SIGNED-FIELDS= (not all fields that need to be signed, were signed).

3.1.5.2 Accessor =REASON= /openid-assertion-error/ ⇒ /string/
=============================================================
     Textual description of error.

3.1.5.3 Accessor =AUTHPROC= /openid-assertion-error/ ⇒ /auth-process/
=====================================================================
     The =AUTH-PROCESS= structure that was being verified.

3.1.5.4 Accessor =MESSAGE= /openid-assertion-error/ ⇒ /message/
===============================================================
     Received message (an association list).

3.1.6 Structure =AUTH-PROCESS=
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Data structure gathering information about an ongoing
    authentication process.

3.1.6.1 Function =AUTH-PROCESS-P= /object/ ⇒ /boolean/
======================================================
     Returns true if /object/ is an =AUTH-PROCESS= structure.

3.1.6.2 Accessor =PROTOCOL-VERSION-MAJOR= /auth-process/ ⇒ /integer/
====================================================================
     Protocol version major number of /auth-process/.

3.1.6.3 Accessor =PROTOCOL-VERSION-MINOR= /auth-process/ ⇒ /integer/
====================================================================
     Protocol version minor number of /auth-process/.

3.1.6.4 Accessor =PROTOCOL-VERSION= /auth-process/ ⇒ /cons/
===========================================================
     Protocol version of an authentication process, as a cons =(MAJOR . MINOR)=.

3.1.6.5 Accessor =CLAIMED-ID= /auth-process/ ⇒ /uri/
====================================================
     Claimed ID of an auth proces.

3.1.6.6 Accessor =OP-LOCAL-ID= /auth-process/ ⇒ /uri/
=====================================================
     OP-local id of an auth process.

3.1.6.7 Accessor =ENDPOINT-URI= /auth-process/ ⇒ /uri/
======================================================
     Discovered endpoint URI.

3.1.6.8 Accessor =RETURN-TO= /auth-process/ ⇒ /uri/
===================================================
     Authentication process' return_to address.

     It is Relying Party's root URI with added HTTP GET parameter
     named =+AUTHPROC-HANDLE-PARAMETER+= whose value is authproc's
     unique handle.

3.1.6.9 Accessor =TIMESTAMP= /auth-process/ ⇒ /universal-time/
==============================================================
     Universal time of authentication process structure's creation.

3.1.6.10 Accessor =XRDS-LOCATION= /auth-process/ ⇒ /uri/
========================================================
     Address of XRDS file used in /auth-process/ discovery.

3.2 OpenID Provider
^^^^^^^^^^^^^^^^^^^

3.2.1 Class =OPENID-PROVIDER=
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    OpenID Provider server abstract class.

    This class should be subclassed, and specialized methods should be
    provided at least for =HANDLE-CHECKID-SETUP= (preferably also for
    =HANDLE-CHECKID-IMMEDIATE=).

3.2.1.1 Accessor =OP-ENDPOINT-URI= /op/ ⇒ /uri/
===============================================
     OpenID Provider instance's endpoint URI

3.2.2 Constant =+INDIRECT-RESPONSE-CODE+=
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    HTTP code used for indirect response redirections.

3.2.3 Function =HANDLE-OPENID-PROVIDER-REQUEST= /op message &key secure-p/ ⇒ /response values/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handle request /message/ for OpenID Provider instance /op/.

    /secure-p/ should be passed by caller to indicate whether it is
    secure to use unencrypted association method.

    Returns two values: first is body, and second is HTTP code.  If
    second value is not returned, 200 OK HTTP code should be assumed.

    On HTTP redirections (second value between 300 and 399 inclusive,
    actually it will be =+INDIRECT-RESPONSE-CODE+=), primary returned
    value will be an URI to redirect user to.

    The same rules apply to all =*-RESPONSE= functions and
    =WITH-INDIRECT-ERROR-HANDLER= form return values.

3.2.4 Function =CANCEL-RESPONSE= /op/ /message/ ⇒ /response values/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Send cancel (authenticaction failure) response to MESSAGE from OP.

3.2.5 Function =SUCCESSFUL-RESPONSE= /op/ /message/ ⇒ /response values/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Return successful response to /message/ by /op/.

3.2.6 Macro =WITH-INDIRECT-ERROR-HANDLER= /&body body/ ⇒ /response values/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handle =INDIRECT-ERROR= in /body/.

    When =INDIRECT-ERROR= condition is signaled, immediately return
    indirect error response.

3.2.7 Function =SIGNAL-INDIRECT-ERROR= /message reason &rest reason-args/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Signal =INDIRECT-ERROR= condition as reply to /message/,
    effectively returning indirect error reply from
    =WITH-INDIRECT-ERROR-HANDLER= block.

    /Reason/ is textual error message format string, with
    /reason-args/ being its arguments.


3.2.8 Generic =HANDLE-CHECKID-IMMEDIATE= /op message/ ⇒ /generalized-boolean/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handle checkid_immediate requests.

    This generic should be specialized on concrete Provider classes to
    perform immediate login checks on /MESSAGE/.  It should return at
    once, either true value (to indicate successful login), or NIL (to
    indicate immediate login failure).

    Default method always fails.

    This generic is called within scope of
    =WITH-INDIRECT-ERROR-HANDLER=.

3.2.9 Generic =USER-SETUP-URL= /op message/ ⇒ /uri/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    URI for user setup to return on failed immediate request.

    When NIL is returned, no user_setup_url is sent in setup_needed
    responses.

    This generic should be specialized on concrete Provider classes to
    provide entry point to user authentication dialogue.

    Default method always returns NIL.

3.2.10 Generic =HANDLE-CHECKID-SETUP= /op message/ ⇒ /response values/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Handle checkid_setup requests.

    This generic should be specialized on concrete Provider classes to
    perform login checks with user dialogue, that would (possibly
    after some HTTP request-response cycles) end in either
    =SUCCESSFUL-RESPONSE=, or in =CANCEL-RESPONSE=.

    Default method always fails.

    This generic is called within scope of
    =WITH-INDIRECT-ERROR-HANDLER=.


3.2.11 Protocol messages
~~~~~~~~~~~~~~~~~~~~~~~~
    Messages passed between OpenID Provider and the Relying Party are
    composed of key-value pairs.  Natural Lisp representation of
    those, and the one used in CL-OpenID, is an association list.  A
    handful of conveniense function is provided to avoid tweaking
    messages on cons level.

3.2.11.1 Function =MAKE-MESSAGE= /&rest parameters/ ⇒ /message/
===============================================================
     Make new message from arbitrary keyword parameters.

     Keyword specifies a message field key (actual key is lowercased
     symbol name), and value following the keyword specifies
     associated value.

     Value can be a string (which will be literal field value), symbol
     (symbol's name will be used as a value), vector of
     (UNSIGNED-BYTE 8) (which will be Base64-encoded), URI object or
     integer (which both will be PRINC-TO-STRING-ed).

     If value is NIL, field won't be included in the message at all.

3.2.11.2 Function =COPY-MESSAGE= /message &rest parameters/ ⇒ /message/
=======================================================================
     Create a copy of MESSAGE, updating PARAMETERS provided as keyword parameters.

     If MESSAGE already includes provided key, new value is used in
     the result; if a key is new, the field will be appended to result
     message.  PARAMETERS are interpreted as by MAKE-MESSAGE function.

3.2.11.3 Function =IN-NS= /message &optional namespace/ ⇒ /message/
===================================================================
     Add openid.namespace /namespace/ to /message/.

     Default namespace is OpenID v2.  Returns updated message alist.

3.2.11.4 Function =MESSAGE-FIELD= /message field-name/ ⇒ /value/
================================================================
     Get value of /field-name/ field from /message/.

3.2.11.5 Function =MESSAGE-V2-P= /message/ ⇒ /boolean/
======================================================
     True if /message/ is an OpenID v2 message (namespace check).

