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
 * MIS report adapter for MS Access
 * @package AIDA
 */

import java.lang.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.sql.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.*;
import net.sourceforge.jtds.jdbc.Driver;
import net.sourceforge.jtds.jdbcx.JtdsDataSource;


public class accessReport extends misReport
{
	/**
	 * Constructor
	 */
	public accessReport()
	{
	}

	/**
	 * Run the report
	 * @param reportCSV the parsed report csv
	 * @param currentDir the directory where the current reports go
	 * @return if the report ran successfully
	 */
	public boolean runReport(LinkedList<String[]> reportDef, HashMap<String, String[]> overrideParameters, String currentDir)
	{
		//check for required connection details
		if(aida.validateConfig(new String[]{"access_database"}))
		{
			aida.logAdd("Running CMIS Access report");

			String slash = File.separator;

			//make the database connection
			Connection conn = openConnection();
	
			if(conn != null)
			{
				aida.logAdd("Connected to database");

				//go through the lines of the report definition
				while(!reportDef.isEmpty())
				{
					try
					{
						String[] reportArray = reportDef.removeFirst();

						//valid report definitions should have only a file name and an SQL query
						if(reportArray.length == 2)
						{
							String fileName = reportArray[0];
							String dest = aida.getConfigValue("aida_dir")+slash+currentDir+slash+fileName;
							String query = reportArray[1];

							int run = 1;
	
							//replace query and run status with override parameters if applicable
							if(overrideParameters.containsKey(fileName))
							{
								query = overrideParameters.get(fileName)[0];
								run = Integer.parseInt(overrideParameters.get(fileName)[1]);
							}
	
							//if the server has no run inhibit flag set
							if(run == 1)
							{
								//check that queries are valid and non-malicious
								if(query.toLowerCase().startsWith("select") && !(query.indexOf(";") >= 0))
								{
									//check if this file name has already been used (files will be concatenated later) and create file
									File destFile = new File(checkDuplicates(dest));
		
									aida.logAdd("Creating "+dest);
		
									if(!destFile.exists()) destFile.createNewFile();
	
									destFile.setWritable(true, false);
						
									FileWriter fileOut = new FileWriter(destFile);

									//run the query
									Statement stmt = conn.createStatement();
									ResultSet rs = stmt.executeQuery(query);
				
									ResultSetMetaData rsmd = rs.getMetaData();
									int numCols = rsmd.getColumnCount();
				
									String[] cols = new String[numCols];
								
									// Get the column names; column indices start from 1
									for (int i=0; i<numCols; i++)
									{
										cols[i] = rsmd.getColumnName(i+1);
									}
				
									//write the data to the file
									while(rs.next())
									{
										String line = "";

										for (int i=0; i<numCols; i++)
										{
											if(i > 0) line += ", ";
											line += "\""+rs.getString(cols[i])+"\"";
										}
				
										fileOut.write(line+"\r\n");
									}
				
									fileOut.flush();
									fileOut.close();
								}
								else
								{
									aida.logAdd("Ignoring illegal query");
									aida.logAdd(query);
								}
							}
							else
							{
								aida.logAdd("Running of "+fileName+" disabled by server");
							}
						}
						else
						{
							aida.logAdd("Incorrect number of arguments to create report");
						}
					}
					catch(SQLException e)
					{
						aida.logAdd("!Report could not be run");
						aida.logAdd("!"+e.getMessage());

						closeConnection(conn);
						return false;
					}
					catch(IOException e)
					{
						aida.logAdd("!Could not write report file");
						aida.logAdd("!"+e.getMessage());

						closeConnection(conn);
						return false;
					}
				}

				closeConnection(conn);

				//concatenate any split reports into one file
				concatenate();
				
				return true;
			}
		}

		return false;
	}

	/*
	 * Open the database connection
	 * @return the database connection
	 */
	protected Connection openConnection()
	{
		try
		{
			DriverManager.registerDriver(new net.sourceforge.jtds.jdbc.Driver());

			Connection conn = java.sql.DriverManager.getConnection("jdbc:odbc:Driver={Microsoft Access Driver (*.mdb)};DBQ="+aida.getConfigValue("access_database")+";DriverID=22;READONLY=true");

			return conn;
		}
		catch(SQLException e)
		{
			aida.logAdd("!Could not open database connection");
			aida.logAdd("!"+e.getMessage());
		}

		return null;
	}

	/*
	 * Close the database connection
	 * @param conn the database connection
	 */
	protected void closeConnection(Connection conn)
	{
		try
		{
			if(conn!=null)
			{
				conn.close();
				conn=null;
			}
		}
		catch(Exception e)
		{
			aida.logAdd("!Could not close database connection");
			aida.logAdd("!"+e.getMessage());
		}
	}
}
