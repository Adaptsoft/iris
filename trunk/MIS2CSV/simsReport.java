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
 * MIS report adapter for SIMS
 * @package AIDA
 */

import java.util.HashMap;
import java.util.LinkedList;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;

public class simsReport extends misReport
{
	/**
	 * Constructor
	 */
	public simsReport()
	{
	}

	/**
	 * Run the report
	 * @param reportDef the parsed report csv
	 * @param currentDir the directory where the current reports go
	 */
	public boolean runReport(LinkedList<String[]> reportDef, HashMap<String, String[]> overrideParameters, String currentDir)
	{
		//check for required connection details
		if(aida.validateConfig(new String[]{"command_reporter", "command_report_importer", "sims_username", "sims_password"}))
		{
			aida.logAdd("Running SIMS report");
	
			try
			{
				boolean definition = true;
	
				while(!reportDef.isEmpty() && definition)
				{
					String[] reportArray = reportDef.removeFirst();

					//get the report definition file and import
					if(reportArray.length == 1)
					{
						String reportFile = aida.getConfigValue("aida_dir")+slash+reportArray[0];

						if(new File(reportFile).exists())
						{
							//execute as a thread
							Process importer = Runtime.getRuntime().exec(aida.getConfigValue("command_report_importer")+" /USER:"+aida.getConfigValue("sims_username")+" /PASSWORD:"+aida.getConfigValue("sims_password")+" /REPORT:\""+reportFile+"\"");
	
							//wait for execution to finish
							int exitVal = importer.waitFor();
	
							//log the process output stream
							logStream(importer);
						}
						else
						{
							definition = false;
							aida.logAdd("!Report Definition could not be found");
						}
					}
					else if(reportArray.length == 2)
					{

						String fileName = reportArray[0];
						String reportName = reportArray[1];

						String override = "";
						int run = 1;

						//get additional params and run status from override parameters if applicable
						if(overrideParameters.containsKey(fileName))
						{
							override = overrideParameters.get(fileName)[0];
							run = Integer.parseInt(overrideParameters.get(fileName)[1]);
						}

						//if the server has no run inhibit flag set
						if(run == 1)
						{
							String dest = aida.getConfigValue("aida_dir")+slash+currentDir+slash+fileName;

							dest = checkDuplicates(dest);

							//create execution command
							String exec = aida.getConfigValue("command_reporter")+" /USER:"+aida.getConfigValue("sims_username")+" /PASSWORD:"+aida.getConfigValue("sims_password")+" /REPORT:\""+reportName+"\" /OUTPUT:\""+dest+"\"";

							if(!override.isEmpty())
							{
								exec += " /PARAMS:\""+override.replace("\"", "\\\"")+"\"";
							}

							aida.logAdd("Executing "+exec);

							//run the command
							Process reporter = Runtime.getRuntime().exec(exec);
	
							//wait for execution to finish
							int exitVal = reporter.waitFor();

							File destFile = new File(dest);

							//Remove first line (which contains field names)
							if(destFile.exists())
							{
								LinkedList<String> storage = new LinkedList<String>();

								BufferedReader reader = new BufferedReader(new FileReader(destFile));
								String ignore = reader.readLine();
								
								while(reader.ready())
								{
									storage.add(reader.readLine());
								}

								reader.close();

								FileWriter fileOut = new FileWriter(destFile, false);

								while (!storage.isEmpty())
								{
									fileOut.write(storage.removeFirst()+"\r\n");
								}
					
								fileOut.flush();
								fileOut.close();
							}

							//log the process output stream
							logStream(reporter);
						}
						else
						{
							aida.logAdd("!Running of "+fileName+" disabled by server");
						}
					}
					else
					{
						aida.logAdd("!Invalid report CSV parameters");
					}
				}

				concatenate();

				return true;
			}
			catch(InterruptedException e)
			{
				aida.logAdd("!SIMS application was interrupted");
				aida.logAdd("!"+e.getMessage());
				return false;
			}
			catch(IOException e)
			{
				aida.logAdd("!SIMS Commander Reporter could not be run");
				aida.logAdd("!"+e.getMessage());
				return false;
			}
		}

		return false;
	}

	/**
	 * Log the information returned from a process
	 * @param pr the process we want to log
	 */
	public void logStream(Process pr)
	{
		try
		{
			BufferedReader bufRead = new BufferedReader(new InputStreamReader(pr.getInputStream()));
	
			String line = bufRead.readLine();
	
			while(line != null)
			{
				if(!line.trim().equals("")) aida.logAdd(line);
				line = bufRead.readLine();
			}
	
			bufRead.close();
		}
		catch(IOException e){}
	}
}
