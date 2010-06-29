/* $Id: TestIDEA.java,v 1.5 2000/07/28 20:06:11 gelderen Exp $
 *
 * Copyright (C) 1995-1999 The Cryptix Foundation Limited.
 * All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject 
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General Licence along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.jce.test;


final class TestIDEA
extends CipherTest
{
    private static final String NAME="IDEA";
    
    private static final String[][] TEST_VALUES = 
    {
        {"00010002000300040005000600070008", 
                                    "0000000100020003", "11FBED2B01986DE5"},
        {"00010002000300040005000600070008", 
                                    "0102030405060708", "540E5FEA18C2F8B1"},
        {"00010002000300040005000600070008", 
                                    "0019324B647D96AF", "9F0A0AB6E10CED78"},
        {"00010002000300040005000600070008", 
                                    "F5202D5B9C671B08", "CF18FD7355E2C5C5"},
        {"00010002000300040005000600070008", 
                                    "FAE6D2BEAA96826E", "85DF52005608193D"},
        {"00010002000300040005000600070008", 
                                    "0A141E28323C4650", "2F7DE750212FB734"},
        {"00010002000300040005000600070008", 
                                    "050A0F14191E2328", "7B7314925DE59C09"},
        {"0005000A000F00140019001E00230028", 
                                    "0102030405060708", "3EC04780BEFF6E20"},
        {"3A984E2000195DB32EE501C8C47CEA60", 
                                    "0102030405060708", "97BCD8200780DA86"},
        {"006400C8012C019001F4025802BC0320", 
                                    "05320A6414C819FA", "65BE87E7A2538AED"},
        {"9D4075C103BC322AFB03E7BE6AB30006", 
                                    "0808080808080808", "F5DB1AC45E5EF9F9"}
    };
        
   
    protected TestIDEA() 
    {
        super(NAME);
    }        


    protected void doIt()
    throws Exception
    {
        testCipher(TEST_VALUES);
    }    
}
