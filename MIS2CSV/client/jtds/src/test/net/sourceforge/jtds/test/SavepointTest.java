// jTDS JDBC Driver for Microsoft SQL Server and Sybase
// Copyright (C) 2004 The jTDS Project
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
package net.sourceforge.jtds.test;

import java.sql.*;

/**
 * @version 1.0
 */
public class SavepointTest extends TestBase {
    public SavepointTest(String name) {
        super(name);
    }

    public void testSavepoint1() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint1 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint1 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint = con.setSavepoint();

        assertNotNull(savepoint);
        assertTrue(savepoint.getSavepointId() == 1);

        try {
            savepoint.getSavepointName();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);
        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint1");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.rollback(savepoint);
        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint1");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 1);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);
    }

    public void testSavepoint2() throws Exception {
        String savepointName = "SAVEPOINT_1";

        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint2 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint2 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint = con.setSavepoint(savepointName);

        assertNotNull(savepoint);
        assertTrue(savepointName.equals(savepoint.getSavepointName()));

        try {
            savepoint.getSavepointId();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);
        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint2");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.rollback(savepoint);

        try {
            con.rollback(null);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.rollback(savepoint);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(null);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint2");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 1);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);

        try {
            con.setSavepoint();
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.setSavepoint(savepointName);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }
    }

    public void testSavepoint3() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint3 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint3 (data) VALUES (?)");

        pstmt.setInt(1, 1);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint1 = con.setSavepoint();

        assertNotNull(savepoint1);
        assertTrue(savepoint1.getSavepointId() == 1);

        pstmt.setInt(1, 2);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint2 = con.setSavepoint();

        assertNotNull(savepoint2);
        assertTrue(savepoint2.getSavepointId() == 2);

        pstmt.setInt(1, 3);
        assertTrue(pstmt.executeUpdate() == 1);

        Savepoint savepoint3 = con.setSavepoint();

        assertNotNull(savepoint3);
        assertTrue(savepoint3.getSavepointId() == 3);

        pstmt.setInt(1, 4);
        assertTrue(pstmt.executeUpdate() == 1);

        pstmt.close();

        stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint3");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 10);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.releaseSavepoint(savepoint1);

        try {
            con.rollback(savepoint1);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint1);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.rollback(savepoint2);

        try {
            con.rollback(savepoint2);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint2);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.rollback(savepoint3);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        try {
            con.releaseSavepoint(savepoint3);
            assertTrue(false);
        } catch (SQLException e) {
            // Ignore, we should get this exception
        }

        con.commit();

        stmt = con.createStatement();
        rs = stmt.executeQuery("SELECT SUM(data) FROM #savepoint3");

        assertTrue(rs.next());
        assertTrue(rs.getInt(1) == 3);
        assertTrue(!rs.next());
        stmt.close();
        rs.close();

        con.setAutoCommit(true);
    }

    /**
     * Test to ensure savepoint ids restart at 1. Also ensures that the
     * procedure cache is managed properly with savepoints.
     */
    public void testSavepoint4() throws Exception {
        Statement stmt = con.createStatement();
        stmt.execute("CREATE TABLE #savepoint4 (data int)");
        stmt.close();

        con.setAutoCommit(false);

        for (int i = 0; i < 3; i++) {
            System.out.println("iteration: " + i);
            PreparedStatement pstmt = con.prepareStatement("INSERT INTO #savepoint4 (data) VALUES (?)");

            pstmt.setInt(1, 1);
            assertTrue(pstmt.executeUpdate() == 1);

            Savepoint savepoint = con.setSavepoint();
            assertNotNull(savepoint);
            assertTrue(savepoint.getSavepointId() == 1);

            try {
                savepoint.getSavepointName();
                assertTrue(false);
            } catch (SQLException e) {
                // Ignore, we should get this exception
            }

            pstmt.setInt(1, 2);
            assertTrue(pstmt.executeUpdate() == 1);
            pstmt.close();

            pstmt = con.prepareStatement("SELECT SUM(data) FROM #savepoint4");
            ResultSet rs = pstmt.executeQuery();

            assertTrue(rs.next());
            assertTrue(rs.getInt(1) == 3);
            assertTrue(!rs.next());
            pstmt.close();
            rs.close();

            con.rollback(savepoint);

            pstmt = con.prepareStatement("SELECT SUM(data) FROM #savepoint4");
            rs = pstmt.executeQuery();

            assertTrue(rs.next());
            assertTrue(rs.getInt(1) == 1);
            assertTrue(!rs.next());
            pstmt.close();
            rs.close();

            con.rollback();
        }

        con.setAutoCommit(true);
    }

    /**
     * Test to ensure savepoints can be created even when no statements have
     * been issued.
     */
    public void testSavepoint5() throws Exception {
        con.setAutoCommit(false);
        con.setSavepoint();
        con.rollback();
        con.setAutoCommit(true);
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SavepointTest.class);
    }
}