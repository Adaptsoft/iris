package net.sourceforge.jtds.test;

import java.sql.*;

/**
 * @created    March 17, 2001
 * @version    1.0
 */
public class UpdateTest extends TestBase {

    public UpdateTest(String name) {
        super(name);
    }

    public void testTemp() throws Exception {
        Statement stmt = con.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);

        stmt.execute("CREATE TABLE #temp (pk INT PRIMARY KEY, f_string VARCHAR(30), f_float FLOAT)");

        // populate in the traditional way
        final int count = 100;
        for (int i = 0; i < count; i++) {
            stmt.execute(
                "INSERT INTO #temp "
                + "VALUES( " + i
                + "," +  "'The String " + i + "'"
                + ", " + i + ")"
            );
        }

        dump(stmt.executeQuery("SELECT Count(*) FROM #temp"));

        //Navigate around
        ResultSet rs = stmt.executeQuery("SELECT * FROM #temp");

        assertTrue(rs.first());
        assertEquals(1, rs.getRow());
        assertTrue(rs.last());
        assertEquals(count, rs.getRow());
        assertTrue(rs.first());
        assertEquals(1, rs.getRow());

        rs.close();
        stmt.close();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UpdateTest.class);
    }
}
