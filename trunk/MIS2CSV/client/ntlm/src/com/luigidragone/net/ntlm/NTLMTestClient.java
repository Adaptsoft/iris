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
 *    NTLMTestClient.java
 *    Copyright (C) 2002 Luigi Dragone
 *
 */

package com.luigidragone.net.ntlm;

import java.security.*;
import java.net.*;
import java.io.*;
import HTTPClient.*;

/**
 * <p>NTLM Test Client.</p>
 * <p>This is a command line tool that uses NTLM authentication to access to a
 * specified URL. It accepts the following arguments:
 * <ol>
 * <li>the name of the cryptographic provider class (e.g. <code>cryptix.jce.provider.CryptixCrypto</code>);</li>
 * <li>the URL of the resource to access to.</li>
 * </ol>
 * Authentication information can be specified through the corresponding system
 * properties. The content of the resource will be dumped to standard output.</p>
 * We want to access to the page <code>http://www.server.com/page.html</code>
 * through an NTLM proxy <code>proxy.domain.com</code> that accepts connection on
 * port 80.<br>
 * We access to proxy from host <code>HOSTDOMAIN\\HOST<code> with the user
 * <code>USERDOMAIN\\user</code> (password <code>"1234567890"</code>), using
 * <a href="http://www.cryptix.org/">Cryptix JCE</a> as cryptographic provider.
 * If all needed classes are accessible through the <var>CLASSPATH</var>
 * we can issue the following command:<br>
 * <pre>
 *  java -Dcom.luigidragone.net.ntlm.host=HOST \
 *    -Dcom.luigidragone.net.ntlm.hostDomain=HOSTDOMAIN \
 *    -Dcom.luigidragone.net.ntlm.user=user \
 *    -Dcom.luigidragone.net.ntlm.userDomain=USERDOMAIN \
 *    -Dcom.luigidragone.net.ntlm.password=1234567890 \
 *    -Dhttp.proxyHost=proxy.domain.com \
 *    -Dhttp.proxyPort=80 \
 *    com.luigidragone.net.ntlm.NTLMTestClient
 *      cryptix.jce.provider.CryptixCrypto
 *      http://www.server.com/page.html
 * </pre>
 * @author Luigi Dragone (<a href="mailto:luigi@luigidragone.com">luigi@luigidragone.com</a>)
 *
 * @version 1.0
 */
public class NTLMTestClient {
  private NTLMTestClient() {};
  public static void main(String[] args) {
    if(args.length != 2) {
      System.err.println("Invalid number of arguments!\n");
      System.err.println("Syntax:");
      System.err.println("\n\tjava com.luigidragone.net.ntlm.NTLMTestClient [crypto-provider] [url]");
      System.err.println("Where:");
      System.err.println("\t[crypto-provider] is the name of the cryptographic provider class;");
      System.err.println("\t[url] the URL of the resource to access to.");
      System.err.println("\nAuthentication information can be specified through the following system properties:");
      System.err.println("\tcom.luigidragone.net.ntlm.host");
      System.err.println("\tcom.luigidragone.net.ntlm.hostDomain");
      System.err.println("\tcom.luigidragone.net.ntlm.user");
      System.err.println("\tcom.luigidragone.net.ntlm.userDomain");
      System.err.println("\tcom.luigidragone.net.ntlm.password");
      System.err.println("The HTTP proxy server can be specified through the standard Java properties (http.proxyHost and http.proxyPort).");
      System.err.println("The content of the resource will be dumped to standard output.");
      System.exit(1);
    }
    String securityProviderClassName = args[0];
    String url = args[1];
    try {
      System.setProperty("java.protocol.handler.pkgs", "HTTPClient");
      if(securityProviderClassName != null) {
        Class securityProvider = Class.forName(securityProviderClassName);
        Security.addProvider((Provider)securityProvider.newInstance());
      }

      HTTPClient.AuthorizationHandler ntlm = new com.luigidragone.net.ntlm.NTLMAuthorizationHandler();
      HTTPClient.AuthorizationInfo.setAuthHandler(ntlm);

      URLConnection conn = new URL(url).openConnection();
      conn.connect();
      System.err.println("Content Length: " + conn.getContentLength());
      System.err.println("Content Type: " + conn.getContentType());
      InputStream is = conn.getInputStream();
      int len = -1;
      byte[] buffer = new byte[1024];
      while((len = is.read(buffer)) != -1)
        System.out.write(buffer, 0, len);
      is.close();
    } catch(Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}