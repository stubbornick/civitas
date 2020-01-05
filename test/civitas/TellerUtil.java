/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas;

import java.io.*;
import java.net.Socket;

/**
 * Some utility methods for checking the status of
 * tabulation tellers, and retrieving statistics from
 * a tabulation teller.
 *
 */
public class TellerUtil {
    public static void main(String[] args) {
        if (args.length != 3) usage();
        String cmd = args[0];
        String host = args[1];
        String port = args[2];

        if ("alive".equalsIgnoreCase(cmd)) {
            boolean result = heartbeat(host, Integer.parseInt(port));
            System.exit(result?1:0);
        }
        else if ("results".equalsIgnoreCase(cmd)) {
            experimentResults(host, Integer.parseInt(port));
        }
        else {
            usage();
        }
    }

    private static void usage() {
        System.err.println("Usage: TellerUtil cmd host port");
        System.err.println("  where cmd is one of 'alive' or 'results' and ");
        System.err.println("     host and port identify the teller.");
        System.err.println("  'TellerUtil alive host port' will exit ");
        System.err.println("     with a-non zero result if the teller is ");
        System.err.println("     responding.");
        System.err.println("  'TellerUtil results host port' will output ");
        System.err.println("     some results.");
        System.exit(0);
    }

    private static boolean heartbeat(String host, int port) {
        try {
            Socket s = new Socket(host, port);
            BufferedReader input = new BufferedReader(new InputStreamReader(s
                                                                            .getInputStream()));
            PrintStream output = new PrintStream(s.getOutputStream());
            output.println("HEARTBEAT");
            output.flush();
            input.readLine();
            s.close();
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }
    private static boolean experimentResults(String host, int port) {
        try {
            Socket s = new Socket(host, port);
            BufferedReader input = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintStream output = new PrintStream(s.getOutputStream());
            output.println("EXPERIMENT_RESULTS");
            output.flush();
            String r = input.readLine();
            while ( !"<END>".equals(r)) {
                System.out.println(r);
                r = input.readLine();
            }
            s.close();
            return true;
        }
        catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
