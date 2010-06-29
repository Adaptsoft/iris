/*
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 *    NTLMAuthorizationHandler.java
 *    Copyright (C) 2002 Luigi Dragone
 *
 */

package com.luigidragone.net.ntlm;

import HTTPClient.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.net.*;

/**
 * <p>
 * This is an NTLM protocol authorization module for
 * <a href="http://www.innovation.ch/">HTTPClient</a>.
 * </p>
 * <p>
 * NTLM is a Microsoft proprietary network authentication protocol used in many
 * situations and HTTPClient is a versatile and extendible component for
 * implementing HTTP client applications.
 * </p>
 * <p>
 * This class relies on {@link NTLM NTLM} class and on HTTPClient package.
 * It also requires a JCE compliant library (e.g., <a href="http://www.cryptix.org/">
 * Cryptix JCE</a>) that implements MD4 and DES algorithms.
 * </p>
 * To perform an authentication the following information are needed:
 * <ul>
 * <li>the host name (with its own domain);</li>
 * <li>the user name (with its own domain);</li>
 * <li>the user password.</li>
 * </ul>
 * Alternatively, the user password can be replaced with its Lan Manager and
 * NT hashed versions. On a Windows system these can be collected in the registry
 * (with a bit of JNI, so), otherwise can be extracted from a SAMBA password
 * file.<br>
 * Notice that the host and user domain could not be the same.
 * </p>
 * <p>Use these data as argument to class constructor to create a new authorization
 * object:<br>
 * <pre>
 *     HTTPClient.AuthorizationHandler ntlm = new NTLMAuthorizationHandler(host, hostDomain, user,
 *       userDomain, password);
 *     HTTPClient.AuthorizationInfo.setAuthHandler(ntlm);
 * </pre>
 * If the client is behind a proxy server, set accordingly the system properties
 * <var>http.proxyHost</var> and <var>http.proxyPort</var>.
 * The authorization handler must be set before opening any connection, thus it
 * could be done in a (static or instance) initializer or in a constructor.
 * After the setting of the authorization handler HTTP connections can be used
 * as usual.<br>
 * It is also possibile store authentication information in the following system
 * properties:
 * <ul>
 * <li><var>com.luigidragone.net.ntlm.host</var>;</li>
 * <li><var>com.luigidragone.net.ntlm.user</var>;</li>
 * <li><var>com.luigidragone.net.ntlm.hostDomain</var>;</li>
 * <li><var>com.luigidragone.net.ntlm.userDomain</var>;</li>
 * <li><var>com.luigidragone.net.ntlm.password</var>.</li>
 * </ul>
 * </p>
 * @author Luigi Dragone (<a href="mailto:luigi@luigidragone.com">luigi@luigidragone.com</a>)
 * @version 1.0.2
 *
 * @see <a href="http://www.innovation.ch/java/ntlm.html">NTLM Authentication Scheme for HTTP</a>
 * @see <a href="http://www.innovation.ch/">HTTPClient</a>
 * @see <a href="http://rfc.net/rfc2616.html">Hypertext Transfer Protocol -- HTTP/1.1</a>
 * @see <a href="http://rfc.net/rfc2617.html">HTTP Authentication: Basic and Digest Access Authentication</a>
 * </p>
 */

public class NTLMAuthorizationHandler implements AuthorizationHandler {
  byte[] nonce = null;
  String host = null;
  String user = null;
  String hostDomain = null;
  String userDomain = null;
  byte[] lmPassword = null;
  byte[] ntPassword = null;
  private static final String NTLM_TAG = "NTLM";
  private static final String PROXY_AUTHENTICATE_HEADER = "Proxy-Authenticate";
  private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";

  /**
   * <p>
   * Build an NTLM authorization handler for the authentication credentials
   * specified by system properties.
   * </p>
   * <p>
   * To specify the authentication information set accordingly the following
   * properties:
   * <ul>
   * <li><var>com.luigidragone.net.ntlm.host</var>;</li>
   * <li><var>com.luigidragone.net.ntlm.user</var>;</li>
   * <li><var>com.luigidragone.net.ntlm.hostDomain</var>;</li>
   * <li><var>com.luigidragone.net.ntlm.userDomain</var>;</li>
   * <li><var>com.luigidragone.net.ntlm.password</var>;</li>
   * </ul>
   * </p>
   * @exception IllegalArgumentException if a required property is undefined
   * @exception javax.crypto.NoSuchPaddingException if there isn't any suitable padding method
   * @exception NoSuchAlgorithmException if there isn't any suitable cipher algorithm
   */
  public NTLMAuthorizationHandler() throws IllegalArgumentException, javax.crypto.NoSuchPaddingException, java.security.NoSuchAlgorithmException {
    this(
      System.getProperty("com.luigidragone.net.ntlm.host", null),
      System.getProperty("com.luigidragone.net.ntlm.hostDomain", null),
      System.getProperty("com.luigidragone.net.ntlm.user", null),
      System.getProperty("com.luigidragone.net.ntlm.userDomain", null),
      System.getProperty("com.luigidragone.net.ntlm.password", null)
    );
  }

  /**
   * <p>
   * Build an NTLM authorization handler for the specified authentication credentials.
   * </p>
   * <p>
   * All the arguments are mandatory (null value are not allowed).
   * </p>
   *
   * @param host the name of the host that is authenticating
   * @param hostDomain the name of the domain to which the host belongs
   * @param user the name of the user
   * @param userDomain the name of the domain to which the user belongs
   * @param lmPassword a 16-bytes array containing the Lan Manager hashed password
   * @param ntPassword a 16-bytes array containing the NT hashed password
   *
   * @exception IllegalArgumentException if a supplied argument is invalid
   */
  public NTLMAuthorizationHandler(String host, String hostDomain, String user, String userDomain, byte[] lmPassword, byte[] ntPassword) throws IllegalArgumentException {
    if(host == null)
      throw new IllegalArgumentException("host : null value not allowed");
    if(hostDomain == null)
      throw new IllegalArgumentException("hostDomain : null value not allowed");
    if(user == null)
      throw new IllegalArgumentException("user : null value not allowed");
    if(userDomain == null)
      throw new IllegalArgumentException("userDomain : null value not allowed");
    if(lmPassword == null)
      throw new IllegalArgumentException("lmPassword : null value not allowed");
    if(ntPassword == null)
      throw new IllegalArgumentException("ntPassword : null value not allowed");
    if(lmPassword.length != 16)
      throw new IllegalArgumentException("lmPassword : illegal size");
    if(ntPassword.length != 16)
      throw new IllegalArgumentException("ntPassword : illegal size");
    this.host = host;
    this.hostDomain = hostDomain;
    this.user = user;
    this.userDomain = userDomain;
    this.lmPassword = lmPassword;
    this.ntPassword = ntPassword;
  }

  /**
   * <p>
   * Build an NTLM authorization handler for the specified authentication credentials.
   * </p>
   * <p>
   * All the arguments are mandatory (null value are not allowed).
   * </p>
   *
   * @param host the name of the host that is authenticating
   * @param hostDomain the name of the domain to which the host belongs
   * @param user the name of the user
   * @param userDomain the name of the domain to which the user belongs
   * @param password the user's password
   *
   * @exception IllegalArgumentException if a supplied argument is invalid
   * @exception javax.crypto.NoSuchPaddingException if there isn't any suitable padding method
   * @exception NoSuchAlgorithmException if there isn't any suitable cipher algorithm
   */
  public NTLMAuthorizationHandler(String host, String hostDomain, String user, String userDomain, String password) throws IllegalArgumentException, javax.crypto.NoSuchPaddingException, java.security.NoSuchAlgorithmException {
    this(host, hostDomain, user, userDomain, NTLM.computeLMPassword(password), NTLM.computeNTPassword(password));
  }

  public HTTPClient.AuthorizationInfo getAuthorization(HTTPClient.AuthorizationInfo parm1, HTTPClient.RoRequest parm2, HTTPClient.RoResponse parm3) throws HTTPClient.AuthSchemeNotImplException, java.io.IOException {
    try {
      String msg;
      if(nonce != null)
        msg = new String(Codecs.base64Encode(NTLM.formatResponse(host, user, userDomain, lmPassword, ntPassword, nonce)));
      else
        msg = new String(Codecs.base64Encode(NTLM.formatRequest(host, hostDomain)));
      return new AuthorizationInfo(parm1.getHost(), parm1.getPort(), NTLM_TAG, "", msg);
    } catch(Exception ex) {
      ex.printStackTrace();
      throw new IOException();
    }
  }

  public HTTPClient.AuthorizationInfo fixupAuthInfo(HTTPClient.AuthorizationInfo parm1, HTTPClient.RoRequest parm2, HTTPClient.AuthorizationInfo parm3, HTTPClient.RoResponse parm4) throws HTTPClient.AuthSchemeNotImplException, java.io.IOException {
    return parm1;
  }

  public void handleAuthHeaders(HTTPClient.Response parm1, HTTPClient.RoRequest parm2, HTTPClient.AuthorizationInfo parm3, HTTPClient.AuthorizationInfo parm4) throws java.io.IOException {
    nonce = null;
    try {
      String challenge = parm1.getHeader(PROXY_AUTHENTICATE_HEADER);
      if((challenge != null) && challenge.startsWith(NTLM_TAG) && challenge.length() > 4)
        nonce = NTLM.getNonce(Codecs.base64Decode(challenge.substring(challenge.indexOf(' ') + 1).trim()).getBytes());
      else {
        challenge = parm1.getHeader(WWW_AUTHENTICATE_HEADER);
        if((challenge != null) && challenge.startsWith(NTLM_TAG) && challenge.length() > 4)
          nonce = NTLM.getNonce(Codecs.base64Decode(challenge.substring(challenge.indexOf(' ') + 1).trim()).getBytes());
      }
    } catch(Exception ex) {
      ex.printStackTrace();
    }
  }

  public void handleAuthTrailers(HTTPClient.Response parm1, HTTPClient.RoRequest parm2, HTTPClient.AuthorizationInfo parm3, HTTPClient.AuthorizationInfo parm4) throws java.io.IOException {}
}

