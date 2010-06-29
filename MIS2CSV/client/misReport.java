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
 * MIS report common functions
 * @package AIDA
 */

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Iterator;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;

abstract class misReport implements reportAdapter
{
	String slash = File.separator;
	HashMap<File, LinkedList<File>> duplicates = new HashMap<File, LinkedList<File>>();

	/**
	 * Concatenate files
	 */
	public void concatenate()
	{
		//merge files specified in duplicates hashmap
		//duplicates are made when a report query is split to ease the load on the MIS
		try
		{
			Iterator it = duplicates.keySet().iterator();

			while(it.hasNext())
			{
				File file = (File)it.next();
				LinkedList<File> concFiles = duplicates.get(file);

				if(!concFiles.isEmpty())
				{
					aida.logAdd("Concatenating files for "+file.getName());
		
					FileWriter fileOut = new FileWriter(file, true);
			
					BufferedReader bufRead;
					File concFile;

					//read all of the files to be concatenated into a single output file
					while (!concFiles.isEmpty())
					{
						concFile = concFiles.removeFirst();
			
						bufRead = new BufferedReader(new FileReader(concFile));
			
						while(bufRead.ready())
						{
							fileOut.write(bufRead.readLine()+"\r\n");
						}
			
						bufRead.close();
					}
			
					fileOut.flush();
					fileOut.close();
				}
			}
		}
		catch(IOException e)
		{
			aida.logAdd("!Files could not be concatenated");
			aida.logAdd("!"+e.getMessage());
		}
	}

	/**
	 * Check for duplicate file names
	 * @param path the path to the file
	 * @return the file name (which may have been changed)
	 */
	public String checkDuplicates(String path)
	{
		File file = new File(path);

		//If this file has already been created
		if(duplicates.containsKey(file))
		{
			try
			{
				int append = duplicates.get(file).size();
	
				LinkedList<File> newVal = duplicates.get(file);

				//create new filename
				File newFile = File.createTempFile(file.getName().substring(0, file.getName().length()-4), ".csv", new File(aida.getConfigValue("aida_dir")));
				newFile.deleteOnExit();
	
				newVal.add(newFile);
	
				//store record of this file in the duplicates hashmap
				duplicates.put(file, newVal);
				
				file = newFile;
			}
			catch(IOException e)
			{
				aida.logAdd("!Duplicate file could not be created");
				aida.logAdd("!"+e.getMessage());
			}
		}
		else
		{
			duplicates.put(file, new LinkedList<File>());
		}

		//return the (possibly renamed) filename
		return file.getAbsolutePath();
	}
}
