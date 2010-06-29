/*
 *    Copyright 2010 Schools Data Services Limited
 *
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

/**
 * Automated IRIS Data Transfer Agent (AIDA)
 * Tool for automated importing of MIS reports into IRIS
 * @package AIDA
 */

import java.io.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;
import java.util.Properties;
import java.text.SimpleDateFormat;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.HttpURLConnection;
import java.security.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import com.luigidragone.net.ntlm.*;
import HTTPClient.HTTPResponse;
import HTTPClient.HTTPConnection;
import HTTPClient.https.Handler;

public class aida
{
	/**
	 * the reports CSV file name
	 */
	protected final String reportCSV = "reports.csv";

	/**
	 * the current reports folder
	 */
	protected final String currentDir = "current";

	/**
	 * the previous reports folder
	 */
	protected final String previousDir = "previous";

	/**
	 * the transmit folder
	 */
	protected final String transmitDir = "transmit";

	/**
	 * the default IRIS folder
	 */
	protected final String defaultIrisDir = "c:\\iris";

	/**
	 * the AIDA version number. This must match the version number set in 'aplc.ini' on the server
	 */
	protected final String version = "1.1";

	/**
	 * this os's path seperator
	 */
	protected static final String slash = File.separator;

	/**
	 * this os's path seperator
	 */
	protected static final String serverUrl = "https://portal.iris.ac";

	/**
	 * this os's path seperator
	 */
	protected static final String reportUpdateLocation = "feed/update.php";

	/**
	 * the formatted revision date/time
	 */
	protected String revision;

	/**
	 * the adapter for this MIS
	 */
	protected reportAdapter reporter;

	/**
	 * the config file location
	 */
	protected static String configFile;

	/**
	 * the parsed config file
	 */
	protected static HashMap<String, String> config = new HashMap<String, String>();

	/**
	 * incremental or full updates
	 */
	protected boolean incremental = true;

	/**
	 * Main function
	 * @param args config file location
	 */
	public static void main(String args[])
	{
		String appDir = new File(System.getProperty("java.class.path")).getParent();

		//Find the location of the ini file
		if(args.length > 0) configFile = args[0];
		else configFile = appDir+slash+"aida.ini";

		aida ai = new aida();

		//Ensure we have a directory for the report files
		if(getConfigValue("aida_dir").equals(""))
		{
			setConfigValue("aida_dir", ai.defaultIrisDir);
		}

		try
		{
			//Lock file prevents multiple instances from being run
			File lockFile = new File(appDir+slash+"aida.lck");
	
			if(!lockFile.exists())
			{
				lockFile.createNewFile();
				lockFile.deleteOnExit();
		
				ai.prepareLog();
		
				if(ai.checkDir(getConfigValue("aida_dir")))
				{
					//create necessary directories
					ai.checkDir(getConfigValue("aida_dir")+slash+ai.getCurrentDir());
					ai.checkDir(getConfigValue("aida_dir")+slash+ai.getPreviousDir());
					ai.checkDir(getConfigValue("aida_dir")+slash+ai.getTransmitDir());
			
					if(validateConfig(new String[]{"mis"}))
					{
						String mis = getConfigValue("mis").toLowerCase();
			
						//Instantiate adapter for specified MIS
						try
						{
							ai.setReporter((reportAdapter)Class.forName(mis+"Report").newInstance());
						}
						catch (ClassNotFoundException e)
						{
							logAdd("!MIS adapter not found for "+mis);
							ai.exit();
						}
						catch (InstantiationException e)
						{
							logAdd("!Could not instantiate "+mis+" Report");
							ai.exit();
						}
						catch (IllegalAccessException e)
						{
							logAdd("!Could not access "+mis+" Report");
							ai.exit();
						}

						//Check if required connection parameters are set
						if(ai.canConnect())
						{
							if(ai.handshake())
							{
								ai.getReportDefinitions();
								LinkedList<String[]> reportDef = ai.parseReportCSV();
								HashMap<String, String[]> overrideParameters = ai.getOverrideParameters();
				
								if(reportDef != null)
								{
									if(ai.runReport(reportDef, overrideParameters))
									{
										LinkedList<String> diffFiles = ai.compareReports();
				
										if(!diffFiles.isEmpty())
										{
											ai.sendReport(diffFiles);
										}

										//Cleanup
										ai.moveFiles(getConfigValue("aida_dir")+slash+ai.getCurrentDir(), getConfigValue("aida_dir")+slash+ai.getPreviousDir());
										ai.emptyDir(ai.getConfigValue("aida_dir")+slash+ai.getTransmitDir());
									}
								}
								else logAdd("!No report definitions exist");
		
								if(ai.syncPasswords())
								{
									ai.finishConnection();
								}
							}
							else logAdd("!Server handshake failed");
						}
						else
						{
							logAdd("!Server connection information is not set. Running locally");
		
							LinkedList<String[]> reportDef = ai.parseReportCSV();
			
							if(reportDef != null)
							{
								if(ai.runReport(reportDef, new HashMap<String, String[]>()))
								{
									LinkedList<String> diffFiles = ai.compareReports();
		
									ai.moveFiles(getConfigValue("aida_dir")+slash+ai.getCurrentDir(), getConfigValue("aida_dir")+slash+ai.getPreviousDir());
								}
							}
							else logAdd("!No report definitions exist");
						}
					}
		
					ai.exit();
				}
				//System.out.println as without IRIS directory there will be nowhere for the log file to go
				else System.out.println("!Iris directory could not be created");
			}
			else
			{
				System.out.println("An AIDA instance is already running");
			}
		}
		catch (IOException e)
		{
			System.out.println("!Locking file read/write error");
			System.out.println("!"+e.getMessage());
			System.exit(0);
		}
	}

	/**
	 * Constructor
	 * Read the config file, parse it and add key/value pairs to the hashmap
	 * @param configFile the location of the configuration file
	 */
	public aida()
	{
		//Create revision date
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
		revision = sdf.format(new Date());

		//Parse the config file
		try
		{
			BufferedReader bufRead = new BufferedReader(new FileReader(configFile));

			while(bufRead.ready())
			{
				String line = bufRead.readLine();

				if(!line.startsWith("#") && line.indexOf("=") != -1)
				{
					//Trim out whitespace, explode at equals and put key/value pairs into the config HashMap
					int splitPos = line.indexOf("=");
					String key = line.substring(0, splitPos).trim();
					String value = line.substring(splitPos+1, line.length()).trim();

					if(!key.equals("") && !value.equals(""))
					{
						config.put(key, value);
					}
				}
			}

			bufRead.close();
		}
		catch (FileNotFoundException e)
		{
			System.out.println("!Configuration file could not be found at "+configFile);
			System.exit(0);
		}
		catch (IOException e)
		{
			System.out.println("!Configuration file read error");
			System.out.println("!"+e.getMessage());
			System.exit(0);
		}
	}

	/**
	 * Do necessary checks for connection to the server
	 * @return if good to connect
	 */
	protected boolean canConnect()
	{
		return aida.validateConfig(new String[]{"iris_site_id", "server_password", "client_password"});
	}
		

	/**
	 * Exchange passwords with the server
	 * @return if handshake was successful
	 */
 	protected boolean handshake()
	{
		try
		{
			logAdd("Performing server handshake");

			//Create connection, send request and receive response
			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] parameters = getNVParameters("handshake");
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);

			if(testConnection(rsp))
			{
				//Check necessary headers
				if(rsp.getHeader("Run Report") != null && rsp.getHeader("Run Report").equals("1"))
				{
					if(rsp.getHeader("Version") != null && rsp.getHeader("Version").equals(version))
					{
						if(rsp.getHeader("Client Password") != null)
						{
							if(rsp.getHeader("Client Password").equals(getConfigValue("client_password")))
							{
								if(rsp.getHeader("Incremental") != null && rsp.getHeader("Incremental").equals("0"))
								{
									incremental = false;
								}

								return true;
							}
							else
							{
								logAdd("!Client passwords do not match");
							}
						}
						else
						{
							logAdd("!No client password received");
						}
					}
					else
					{
						logAdd("!Incorrect AIDA version");
					}
				}
				else
				{
					logAdd("!Reports halted by server");
				}
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not perform handshake");
			logAdd("!"+e.getMessage());
		}

		return false;
	}

	/**
	 * Connect to the IRIS server and retrieve all report updates
	 * Get updated file listings then retrieve files
	 */
	public void getReportDefinitions()
	{
		try
		{
			logAdd("Retrieving report definitions");

			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] parameters = getNVParameters("listFiles");
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);

			if(testConnection(rsp))
			{
				//Receive list of files to be downloaded and their md5 hashes
				LinkedList<String> files = new LinkedList<String>();
				LinkedList<String> hashes = new LinkedList<String>();

				InputStreamReader inRead = new InputStreamReader(rsp.getInputStream());
				BufferedReader bufRead = new BufferedReader(inRead);

				String fileName;
				String hash;

				//Catches any unexpected output/errors from the server and diverts it into the system log rather than the file list
				boolean unexp = false;

				String line = bufRead.readLine();

				while(line != null)
				{
					//Matching '<' because unexpected PHP output/errors should be wrapped in HTML tags
					if(line.indexOf('<') >= 0) unexp = true;

					if(unexp) logAdd(line);
					else 
					{
						//Chop input into filename and md5 hash
						int splitPos = line.indexOf(",");
						fileName = line.substring(0, splitPos).trim();
						hash = line.substring(splitPos+1, line.length()).trim();

						//Make sure the filename and hash are valid
						if(!fileName.equals("") && !hash.equals(""))
						{
							files.add(fileName);
							hashes.add(hash);

							logAdd("Found " + fileName + " " +hash);
						}
					}

					line = bufRead.readLine();
				}

				bufRead.close();
				inRead.close();

				while(!files.isEmpty())
				{
					fileName = files.removeFirst();
					hash = hashes.removeFirst();

					File file = new File(getConfigValue("aida_dir")+slash+fileName);

					//If we don't already have that file, download it
					if(!file.exists() || !getMD5Hash(file).equals(hash))
					{
						retrieveFile(fileName);
					}
				}
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not receive file listings");
			logAdd("!"+e.getMessage());
		}
	}

	/**
	 * Retreive a file from the IRIS server and place it in the relevant MIS folder
	 * @param fileName
	 */
	protected void retrieveFile(String fileName)
	{
		try
		{
			logAdd("Retrieving "+fileName);

			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] extraParams = {new HTTPClient.NVPair("file_name", fileName)};
			HTTPClient.NVPair[] parameters = getNVParameters("sendFile", extraParams);
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);
	
			if(testConnection(rsp))
			{
				//Stream the response data into a file
				InputStream is = rsp.getInputStream();

				File saveFile = new File(getConfigValue("aida_dir")+slash+fileName);

				//Delete previous version of this file
				if(saveFile.exists()) saveFile.delete();

				saveFile.createNewFile();
	
				OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(saveFile));
	
				byte[] buffer = new byte[1024];
				int dataIn;
	
				while ((dataIn = is.read(buffer)) != -1)
				{
					fileOut.write(buffer, 0, dataIn);
				}
	
				fileOut.flush();
				fileOut.close();
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not download "+fileName);
			logAdd("!"+e.getMessage());
		}
	}

	/**
	 * Connect to the IRIS server and retrieve the override parameters
	 * Parse the CSV then return
	 * @return the parsed parameters
	 */
	public HashMap<String, String[]> getOverrideParameters()
	{
		HashMap<String, String[]> parsedCSV = new HashMap<String, String[]>();

		try
		{
			logAdd("Retrieving override parameters");

			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] parameters = getNVParameters("sendOverrideParameters");
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);

			if(testConnection(rsp))
			{
				//Read the response input stream
				InputStreamReader inRead = new InputStreamReader(rsp.getInputStream());

				if(inRead.ready())
				{
					//Parse input stream as CSV
					CSVReader reader = new CSVReader(inRead);

					String[] line;

					while ((line = reader.readNext()) != null)
					{
						if(line.length == 3)
						{
							//Store override parameters with report filename as the HashMap key and override data then run flag in an array
							parsedCSV.put(line[0], new String[]{line[1], line[2]});
						}
					}
	
					reader.close();
					inRead.close();
				}
				else
				{
					logAdd("No override parameters exist for this site");
				}
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not receive override parameters");
			logAdd("!"+e.getMessage());
		}

		return parsedCSV;
	}

	/**
	 * Prepares reports for sending to the server
	 * @param files the files to send
	 */
	public void sendReport(LinkedList<String> files)
	{
		logAdd("Sending report files");

		while (!files.isEmpty())
		{
			transmitFile(files.removeFirst());
		}
	}

	/**
	 * Transmit a report file to the server
	 * @param fileName the name of the file to be sent
	 */
	public void transmitFile(String fileName)
	{
		try
		{
			logAdd("Transmitting "+fileName);

			HTTPClient.HTTPConnection conn = makeConnection();
			
			// create the NVPair's for the form data to be submitted and do the encoding
			HTTPClient.NVPair[] headers  = new HTTPClient.NVPair[1];
			HTTPClient.NVPair[] files = { new HTTPClient.NVPair("file_upload", getConfigValue("aida_dir")+slash+transmitDir+slash+fileName) };
			HTTPClient.NVPair[] parameters = getNVParameters("receiveFile");
			
			byte[] form_data = HTTPClient.Codecs.mpFormDataEncode(parameters, files, headers);
			
			// POST the form data, as indicated by the method attribute
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, form_data, headers);

			testConnection(rsp);

			if(rsp.getHeader("Upload Status") != null)
			{
				logAdd(rsp.getHeader("Upload Status"));
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch(IOException e)
		{
			logAdd("!Could not transmit file");
			logAdd("!"+e.getMessage());
		}
	}

	/**
	 * Send new client password to the server, retrieve new server password and write it to the config file
	 * @return has password sync completed successfully
	 */
	protected boolean syncPasswords()
	{
		logAdd("Synchronising passwords");

		//Create new pseudo-random client password
		String chars = "1234567890abcdef";

		char[] password = new char[32];

		for (int i=0; i < password.length; i++)
		{
			password[i] = chars.charAt((int)(Math.random() * chars.length()));
		}

		String client_password = new String(password);

		//Write it to the config file
		writeConfig("client_password", client_password);

		//Send client password to the server and receive new server password
		try
		{
			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] extraParams = {new HTTPClient.NVPair("client_password", client_password)};
			HTTPClient.NVPair[] parameters = getNVParameters("syncPassword", extraParams);

			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);

			if(testConnection(rsp))
			{
				if(rsp.getHeader("Server Password") != null)
				{
					writeConfig("server_password", rsp.getHeader("Server Password"));
					return true;
				}
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not receive new password");
			logAdd("!"+e.getMessage());
		}

		return false;
	}

	/**
	 * Send 'finished' flag to server so that it can do it's final tasks
	 */
	protected void finishConnection()
	{
		logAdd("Finishing connection");

		try
		{
			HTTPClient.HTTPConnection conn = makeConnection();
			HTTPClient.NVPair[] parameters = getNVParameters("finishConnection");
			HTTPClient.HTTPResponse rsp = conn.Post(reportUpdateLocation, parameters);

			if(testConnection(rsp))
			{
				if(rsp.getHeader("Connection Finished") == null || rsp.getHeader("Connection Finished").equals("false"))
				{
					logAdd("!Connection could not be finished");
				}
				else
				{
					logAdd("Connection Finished");
				}
			}
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
		}
		catch (IOException e)
		{
			logAdd("!Server connection error - could not finish connection");
			logAdd("!"+e.getMessage());
		}
	}

	/**
	 * Make a connection to the IRIS server
	 * @return the connection object
	 */
	protected HTTPClient.HTTPConnection makeConnection() throws IOException
	{
		logAdd("Connecting to server at " + serverUrl);
		URL url = new URL(serverUrl);

		int port = 80;

		if(!getConfigValue("server_port").equals(""))
		{
			port = Integer.parseInt(getConfigValue("server_port"));
		}
		else if(url.getProtocol().equals("https"))
		{
			port = 443;
		}

		logAdd("Protocol:" + url.getProtocol() + " Host:" + url.getHost() + " Port:" + port);

		if(!getConfigValue("proxy_host").equals("") && !getConfigValue("proxy_port").equals(""))
		{
			logAdd("Setting proxy server " + getConfigValue("proxy_host")+":"+getConfigValue("proxy_port"));
			HTTPClient.HTTPConnection.setProxyServer(getConfigValue("proxy_host"), Integer.parseInt(getConfigValue("proxy_port")));
		}

		if(!getConfigValue("proxy_username").equals("") && !getConfigValue("proxy_password").equals("") && !getConfigValue("ntlm_enable").equals("true"))
		{
			logAdd("Passing proxy username and password");
			//getConfigValue("proxy_realm")

			String realm = getConfigValue("proxy_realm");
			if(realm.isEmpty()) realm = null;

			HTTPClient.AuthorizationInfo.addBasicAuthorization(getConfigValue("proxy_host"), Integer.parseInt(getConfigValue("proxy_port")), realm, getConfigValue("proxy_username"), getConfigValue("proxy_password"));
		}
		else if(getConfigValue("ntlm_enable").equals("true"))
		{
			try {
				logAdd("Initializing NTLM connection.");
				InetAddress host = InetAddress.getByName(getConfigValue("ntlm_windowsDomain"));
				String ip = host.getHostAddress();

				Security.addProvider(new cryptix.jce.provider.CryptixCrypto());
				HTTPClient.AuthorizationHandler ntlm = new NTLMAuthorizationHandler(
					ip,
					getConfigValue("ntlm_windowsDomain"),
					getConfigValue("ntlm_user"),
					getConfigValue("ntlm_windowsDomain"),
					getConfigValue("ntlm_password")
				);
				HTTPClient.AuthorizationInfo.setAuthHandler(ntlm);
			} catch( Exception e) {
				logAdd("!Failed to initialize NTLM connection:  "+e.getMessage());
				System.exit(0);
			}
		}

		//Create the connection object
		HTTPClient.HTTPConnection conn = new HTTPClient.HTTPConnection(url.getProtocol(), url.getHost(), port);
		return conn;
	}

	/**
	 * Test the IRIS server connection
	 * @param rsp the HTTP response object
	 * @return if the connection is good
	 */
	protected boolean testConnection(HTTPClient.HTTPResponse rsp)
	{
		//Check the status code and the authenticated flag
		try
		{
			if (rsp.getStatusCode() >= 300)
			{
				logAdd("!Could not find server script - Error Code "+rsp.getStatusCode());
				return false;
			}
			else
			{
				if(!getConfigValue("log_headers").equals("") && !getConfigValue("log_headers").equals("false"))
				{
					logAdd("HTTP Headers:");
		
					LinkedList<String[]> headers = rsp.getHeaders();
		
					while(!headers.isEmpty())
					{
						String[] header = headers.removeFirst();
						logAdd(header[0]+": "+header[1]);
					}
				}
		
				if(rsp.getHeader("Authenticated") == null || rsp.getHeader("Authenticated").equals("false"))
				{
					logAdd("!Server authentication failed");
					return false;
				}
			}
	
			return true;
		}
		catch(HTTPClient.ModuleException e)
		{
			logAdd("!A module exception occurred");
			logAdd("!"+e.getMessage());
			return false;
		}
		catch (IOException e)
		{
			logAdd("!Could not read headers");
			logAdd("!"+e.getMessage());
			return false;
		}
	}

	/**
	 * Creates NVPair parameters for the server request
	 * @param action the action for this request
	 * @return the NVPair array
	 */
	protected HTTPClient.NVPair[] getNVParameters(String action)
	{
		return getNVParameters(action, null);
	}

	/**
	 * Creates NVPair parameters for the server request
	 * @param action the action for this request
	 * @param extras any extra parameters that need to be sent
	 * @return the NVPair array
	 */
	protected HTTPClient.NVPair[] getNVParameters(String action, HTTPClient.NVPair[] extras)
	{
		LinkedList<HTTPClient.NVPair> parameters = new LinkedList<HTTPClient.NVPair>();

		parameters.add(new HTTPClient.NVPair("site_id", getConfigValue("iris_site_id")));
		parameters.add(new HTTPClient.NVPair("password", getConfigValue("server_password")));
		parameters.add(new HTTPClient.NVPair("revision", revision));
		parameters.add(new HTTPClient.NVPair("action", action));

		if(extras != null)
		{
			for(int i=0; i<extras.length; i++)
			{
				parameters.add(extras[i]);
			}
		}

		return parameters.toArray(new HTTPClient.NVPair[0]);
	}

	/**
	 * Parse the report CSV file
	 * @return the parsed file
	 */
	protected LinkedList<String[]> parseReportCSV()
	{
		//run the report definitions through the CSV reader
		try
		{
			logAdd("Parsing report CSV file");

			LinkedList<String[]> parsedCSV = new LinkedList<String[]>();

			CSVReader reader = new CSVReader(new FileReader(getConfigValue("aida_dir")+slash+reportCSV));

			String[] line;
			while ((line = reader.readNext()) != null)
			{
				parsedCSV.add(line);
			}

			reader.close();

			return parsedCSV;
		}
		catch (FileNotFoundException e)
		{
			logAdd("!Report CSV file could not be found");
			return null;
		}
		catch (IOException e)
		{
			logAdd("!Report CSV file read error");
			logAdd("!"+e.getMessage());
			return null;
		}

	}

	/**
	 * Call the MIS adapter to run the report
	 * @param reportDef the parsed report csv file
	 * @param overrideParameters the override parameters for this site
	 * @return whether or not the report has run successfully
	 */
	public boolean runReport(LinkedList<String[]> reportDef, HashMap<String, String[]> overrideParameters)
	{
		logAdd("Running reports");
		return reporter.runReport(reportDef, overrideParameters, currentDir);
	}

	/**
	 * Compare the current and previous reports
	 * @return the names of files that have changed
	 */
	public LinkedList<String> compareReports()
	{
		logAdd("Comparing reports");

		File[] currFiles = new File(getConfigValue("aida_dir")+slash+currentDir).listFiles();
		File[] prevFiles = new File(getConfigValue("aida_dir")+slash+previousDir).listFiles();

		LinkedList<String> diffNames = new LinkedList<String>();

		//If the server is asking for incremental reports and there are previous reports in the previous directory
		if(incremental && prevFiles.length > 0)
		{
			//go through all files in the current directory (where the mis adaptors will have put the data)
			for(int i=0; i<currFiles.length; i++)
			{
				File prevFile = new File(getConfigValue("aida_dir")+slash+previousDir+slash+currFiles[i].getName());

				if(prevFile.exists())
				{
					//compare MD5 hashes
					if(!(getMD5Hash(currFiles[i]).equals(getMD5Hash(prevFile))))
					{
						//iff the diffreports function has found differences it will have created the diff file in the transmit directory
						if(diffReports(currFiles[i]))
						{
							//add it to the list of files to be transmitted
							diffNames.add(currFiles[i].getName());
						}
					}
				}
				else
				{
					if(diffReports(currFiles[i]))
					{
						diffNames.add(currFiles[i].getName());
					}
				}
			}

			if(diffNames.isEmpty())
			{
				logAdd("Reports are identical to previous");
			}
		}
		else
		{
			if(currFiles.length > 0)
			{
				for(int i=0; i<currFiles.length; i++)
				{
					if(diffReports(currFiles[i]))
					{
						diffNames.add(currFiles[i].getName());
					}
				}
			}
			else
			{
				logAdd("No reports generated");
			}
		}

		return diffNames;
	}


	/**
	 * Run a diff on the new report and the previous one
	 * @param currFile the new file to run a diff on
	 * @return if differences exist
	 */
	protected boolean diffReports(File currFile)
	{
		try
		{
			logAdd("Diffing "+currFile.getName());

			LinkedList<String> differences = new LinkedList<String>();

			File prevFile = new File(getConfigValue("aida_dir")+slash+previousDir+slash+currFile.getName());

			//If the server is asking for incremental reports and there is a corresponding previous report
			if(incremental && prevFile.exists())
			{
				LinkedList<String> currLines = new LinkedList<String>();
				LinkedList<String> prevLines = new LinkedList<String>();
	
				CSVReader currRead = new CSVReader(new FileReader(currFile));
	
				//populate linked list from data file
				while(currRead.ready())
				{
					currLines.add(currRead.readNextAsString());
				}
	
				CSVReader prevRead = new CSVReader(new FileReader(prevFile));
				
				//populate linked list from data file
				while(prevRead.ready())
				{
					prevLines.add(prevRead.readNextAsString());
				}
	
				while (!currLines.isEmpty())
				{
					String currLine = currLines.removeFirst();

					//if the line is in the previous data then it can be disregarded
					if(prevLines.contains(currLine))
					{
						prevLines.remove(currLine);
					}
					//if the line is not in the previous data then it must be new
					else
					{
						differences.add("1,"+currLine);
					}
				}

				//any lines left in the previous data must have been deleted in the current data
				while (!prevLines.isEmpty())
				{
					differences.add("0,"+prevLines.removeFirst());
				}
			}
			else
			{
				CSVReader currRead = new CSVReader(new FileReader(currFile));

				//whole file will be marked as additions/updates and transmitted
				while(currRead.ready())
				{
					differences.add("1,"+currRead.readNextAsString());
				}
			}

			//Write the differences to a file to be transmitted to the server
			if(!differences.isEmpty())
			{
				logAdd("Creating "+getConfigValue("aida_dir")+slash+transmitDir+slash+currFile.getName());

				FileWriter fileOut = new FileWriter(getConfigValue("aida_dir")+slash+transmitDir+slash+currFile.getName(), false);
		
				while (!differences.isEmpty())
				{
					fileOut.write(differences.removeFirst()+"\r\n");
				}
		
				fileOut.flush();
				fileOut.close();

				return true;
			}
		}
		catch (FileNotFoundException e)
		{
			logAdd("!Files could not be found");
			return false;
		}
		catch (IOException e)
		{
			logAdd("!File read error");
			logAdd("!"+e.getMessage());
			return false;
		}

		return false;
	}

	/**
	 * Create an MD5 hash on a file
	 * @param file the name of the file to hash
	 * @return the MD5 hash
	 */
	protected String getMD5Hash(File file)
	{
		logAdd("Creating MD5 hash on "+file.getPath());

		String hash = "";

		try
		{
			FileReader fileRead = new FileReader(file);
			MessageDigest md = MessageDigest.getInstance("MD5");

			char[] chars = new char[1024];
			int charsRead = 0;
	
			do
			{
				charsRead = fileRead.read(chars, 0, chars.length);

				if(charsRead >= 0)
				{
					md.update(new String(chars, 0, charsRead).getBytes());
				}
			}
			while(charsRead >= 0);

			hash = new BigInteger(1, md.digest()).toString(16);
		}
		catch (NoSuchAlgorithmException e)
		{
			logAdd("Could not create MD5 message digester");
		}
		catch (IOException e)
		{
			logAdd("Could not read file "+file.getName());
		}
		
		logAdd("MD5 hash: "+hash);
		
		return hash;
	}

	/**
	 * Create directories if required and check write permissions
	 * @param dir the folder to be checked/created
	 * @return if the folder was created (and hence also is writable) or if it already exists and is writable
	 */
	protected boolean checkDir(String dir)
	{
		logAdd("Checking folder "+dir);

		File newDir = new File(dir);

		if(!newDir.exists())
		{
			try
			{
				newDir.mkdirs();
			}
			catch (SecurityException e)
			{
			}

			//mkdirs() seems to return true and never throw a security exception whether or not it was able to create the folder so this check is needed	
			if(writableDir(dir))
			{
				logAdd(dir+" has been created");
				return true;
			}
			else
			{
				logAdd("!"+dir+" could not be created - check permissions");
				System.out.println(dir+" could not be created - check permissions");
				return false;
			}
		}
		else if(!writableDir(dir))
		{
			logAdd("!"+dir+" is not writable");
			System.out.println(dir+" is not writable");
			return false;
		}

		return true;
	}


	/**
	 * Check if a directory is writable
	 * This seems to be the best way of checking write permissions - yeah it's a bodge but hey, java blows
	 * @param dir the folder to be checked
	 * @return if the folder is writable
	 */
	public boolean writableDir(String dir)
	{
		File newDir = new File(dir);

		if(newDir.exists())
		{
			try
			{
				File tmpFile = new File(dir+slash+"test.tmp");
				tmpFile.createNewFile();
	
				if(tmpFile.exists())
				{
					tmpFile.delete();
					return true;
				}
			}
			catch(IOException e)
			{
			}
		}

		return false;
	}

	/**
	 * Empty a directory
	 * @param dir the folder to be emptied
	 */
	protected void emptyDir(String dir)
	{
		logAdd("Emptying folder "+dir);

		File[] files = new File(dir).listFiles();

		for(int i=0; i<files.length; i++)
		{
			try
			{
				if(!files[i].isDirectory())
				{
					if(!files[i].delete())
					{
						logAdd("!"+files[i].getName()+" could not be deleted");
					}
				}
			}
			catch (SecurityException e)
			{
				logAdd("!"+files[i].getName()+" could not be deleted");
			}
		}
	}

	/**
	 * Copy file
	 * @param inputFile the file to copy
	 * @param destDir the source folder
	 */
	protected void copyFile(File inputFile, String destDir)
	{
		logAdd("Copying "+inputFile.getName()+" to "+destDir);

		if(checkDir(destDir))
		{
			try
			{
				File outputFile = new File(destDir+slash+inputFile.getName());
				outputFile.setWritable(true, false);

				FileInputStream fis  = new FileInputStream(inputFile);
				FileOutputStream fos = new FileOutputStream(outputFile);
	
				byte[] buf = new byte[1024];
				int i = 0;
				while ((i = fis.read(buf)) != -1)
				{
					fos.write(buf, 0, i);
				}

				fos.flush();
				fos.close();
			}
			catch (FileNotFoundException e)
			{
				logAdd("Could not open "+destDir);
			}
			catch (IOException e)
			{
				logAdd("Could not read file "+inputFile.getName());
			}
		}
		else
		{
			logAdd(destDir+" is not accessable");
		}
	}

	/**
	 * Move files
	 * @param sourceDir the source folder
	 * @param destDir the source folder
	 */
	protected void moveFiles(String sourceDir, String destDir)
	{
		if(checkDir(sourceDir) && checkDir(destDir))
		{
			try
			{
				logAdd("Moving files from "+sourceDir+" to "+destDir);

				File source = new File(sourceDir);
				File dest = new File(destDir);
	
				emptyDir(destDir);

				File[] files = source.listFiles();

				for(int i=0; i<files.length; i++)
				{
					copyFile(files[i], destDir);
				}

				emptyDir(sourceDir);

			}
			catch (SecurityException e)
			{
				logAdd("!"+sourceDir+" could not be moved to "+destDir+"");
			}
		}
	}

	/**
	 * Return the current folder
	 * @return the current folder
	 */
	public String getCurrentDir()
	{
		return currentDir;
	}

	/**
	 * Return the previous folder
	 * @return the previous folder
	 */
	public String getPreviousDir()
	{
		return previousDir;
	}

	/**
	 * Return the transmit folder
	 * @return the transmit folder
	 */
	public String getTransmitDir()
	{
		return transmitDir;
	}

	/**
	 * Set the report adapter
	 * @param r the report adapter
	 */
	public void setReporter(reportAdapter r)
	{
		reporter = r;
	}

	/**
	 * Get the report adapter
	 * @return the reportAdapter object
	 */
	public reportAdapter getReporter()
	{
		return reporter;
	}

	/**
	 * Get config value
	 * @param key the config HashMap key
	 * @return the config value associated with that key
	 */
	public static String getConfigValue(String key)
	{
		if(config.containsKey(key)) return config.get(key);
		else return "";
	}

	/**
	 * Set config value
	 * @param key the key to be inserted
	 * @param value the value to be inserted
	 */
	public static void setConfigValue(String key, String value)
	{
		config.put(key, value);
	}

	/**
	 * Write new key/value to the config file
	 * @param key the key to write
	 * @param value the new value
	 */
	protected void writeConfig(String key, String value)
	{
		try
		{
			logAdd("Writing "+key+" to configuration file");

			setConfigValue(key, value);

			LinkedList<String> config = new LinkedList<String>();

			BufferedReader bufRead = new BufferedReader(new FileReader(configFile));

			//read in the config file to a linked list
			//Trim out whitespace, explode at equals and put key/value pairs into the config linked list, replacing the value at the given key
			while(bufRead.ready())
			{
				String line = bufRead.readLine();

				int splitPos = line.indexOf("=");

				if(splitPos >= 0)
				{
					String confKey = line.substring(0, splitPos).trim();
	
					if(confKey.equals(key))
					{
						line = key + " = " + value;
					}
				}

				config.add(line);
			}

			bufRead.close();

			FileWriter fileOut = new FileWriter(configFile);

			//write out the updated config file
			while (!config.isEmpty())
			{
				fileOut.write(config.removeFirst()+"\r\n");
			}

			fileOut.flush();
			fileOut.close();
		}
		catch (FileNotFoundException e)
		{
			logAdd("!Configuration file could not be found at "+configFile);
			exit();
		}
		catch (IOException e)
		{
			logAdd("!Configuration file read error");
			logAdd("!"+e.getMessage());
			exit();
		}
	}

	/**
	 * Check that all required keys are present
	 * @param reqKeys the keys to check for
	 * @return if the config is valid
	 */
	public static boolean validateConfig(String[] reqKeys)
	{
		logAdd("Validating configuration");

		for(int i=0; i<reqKeys.length; i++)
		{
			if(!config.containsKey(reqKeys[i]))
			{
				logAdd("!Invalid configuration. Required key "+reqKeys[i]+" could not be found");
				return false;
			}
		}

		return true;
	}

	/**
	 * Insert into the log
	 * @param text the text to be inserted
	 */
	public static void logAdd(String text)
	{
		try
		{
			File logFile = new File(getConfigValue("aida_dir")+slash+"iris.log");
	
			FileWriter fileOut = new FileWriter(logFile, true);
	
			fileOut.write(text+"\r\n");
	
			fileOut.flush();
			fileOut.close();
		}
		catch (IOException e)
		{
			System.out.println("Cannot write to IRIS log file - "+text);
		}
	}

	/**
	 * Prepare the log for writing
	 */
	protected void prepareLog()
	{
		try
		{
			File irisDir = new File(getConfigValue("aida_dir"));

			if(!irisDir.exists())
			{
				irisDir.mkdirs();
			}

			File logFile = new File(getConfigValue("aida_dir")+slash+"iris.log");

			if(!logFile.exists()) logFile.createNewFile();
			else
			{
				//if the log is over 50k, rename it to iris.old and create a new one
				if(logFile.length() > 50000)
				{
					File oldLog = new File(getConfigValue("aida_dir")+slash+"iris.old");

					if(oldLog.exists()) oldLog.delete();

					logFile.renameTo(oldLog);

					logFile = new File(getConfigValue("aida_dir")+slash+"iris.log");
					logFile.createNewFile();
				}
			}

			FileWriter fileOut = new FileWriter(logFile, true);

			//calculate the data and time and write to config file

			Calendar cal = Calendar.getInstance();

			String minute;
			if(cal.get(Calendar.MINUTE) < 10) minute = "0" + cal.get(Calendar.MINUTE);
			else minute = "" + cal.get(Calendar.MINUTE);

			String timestamp = cal.get(Calendar.HOUR_OF_DAY)+":"+minute+" "+cal.get(Calendar.DATE)+"/"+(cal.get(Calendar.MONTH)+1)+"/"+cal.get(Calendar.YEAR)+"\r\n";

			fileOut.write("\r\n"+timestamp+"\r\n");
			fileOut.write("Configuration file parsed"+"\r\n");

			fileOut.flush();
			fileOut.close();
		}
		catch (IOException e)
		{
			System.out.println("Cannot write to IRIS log file at "+getConfigValue("aida_dir")+slash+"iris.log");
		}
	}

	protected void exit()
	{
		logAdd("\r\n");
		System.exit(0);	
	}
}
