/*
 * This file is part of the Civitas software distribution.
 * Copyright (c) 2007-2008, Civitas project group, Cornell University.
 * See the LICENSE file accompanying this distribution for further license
 * and copyright information.
 */
package civitas.common;

import java.io.*;

import jif.lang.Label;
import civitas.crypto.common.Base64;

/**
 * Some miscellaneous utility functions.
 */
public class Util {
    public static String currentVersion() {
        return "Civitas-v0.1";
    }

    public static String stripLeadingWhitespace(String s) {
        if (s == null) return s;
        int i = 0, length = s.length();
        while (i < length && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        if (i == 0) return s;
        if (i == length) return "";
        return s.substring(i);
    }

    public static String stripTrailingWhitespace(String s) {
        if (s == null) return s;
        int i = s.length();
        while (i > 0 && Character.isWhitespace(s.charAt(i-1))) {
            i--;
        }
        if (i == s.length()) return s;
        if (i <= 0) return "";
        return s.substring(0,i);
    }
    public static String stripTrailingLeadingWhitespace(String s) {
        if (s == null) return s;
        int length = s.length();
        int l = 0, r = length;
        while (l < length && Character.isWhitespace(s.charAt(l))) {
            l++;
        }
        while (r > l && Character.isWhitespace(s.charAt(r-1))) {
            r--;
        }
        if (l == r) return "";
        if (l == 0 && r == length) return s;
        return s.substring(l,r);
    }

    /*
     * Some simple tests
     */
    public static void main(String[] args) {
        System.err.println(escapeString("Hello "));
        System.err.println(escapeString("Hello mum & da'd "));
        System.err.println(unescapeString(escapeString("Hello ")));
        System.err.println(unescapeString(escapeString("Hello mum & da'd ")));
        String s = "askfjjnalskdfhlasdfh alskjdfh ";
        System.err.println(escapeString(s) == s);
        System.err.println(unescapeString(escapeString(s)) == s);
    }

    static boolean[] is_meta = new boolean[128];
    static char[] metachars = { '&', '<', '>', ',', '"' };
    static {
        for (int i = 0; i < metachars.length; i++)
            is_meta[(int)metachars[i]] = true;
    }
    /**
     * Escape the characters:
     *  & (&amp;)
     *  < (&lt;)
     *  > (&gt;)
     *  , (&apos;)
     *  " (&quot;)
     */
    public static String escapeString(final String s) {
        StringWriter sb = new StringWriter();
        escapeString(s, null, new PrintWriter(sb));
        return sb.toString();
    }
    public static void escapeString(final String s, final Label lbl, final PrintWriter sb) {
        if (s == null || sb == null) return;
        int n = s.length();
        int lastOut = -1;

        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (!is_meta[(int)c]) continue;
            switch (c) {
            case '&':
                if (lastOut != i-1) sb.append(s.substring(lastOut+1, i));
                sb.append("&amp;");
                lastOut = i;
                break;
            case '<':
                if (lastOut != i-1) sb.append(s.substring(lastOut+1, i));
                sb.append("&lt;");
                lastOut = i;
                break;
            case '>':
                if (lastOut != i-1) sb.append(s.substring(lastOut+1, i));
                sb.append("&gt;");
                lastOut = i;
                break;
            case '\'':
                if (lastOut != i-1) sb.append(s.substring(lastOut+1, i));
                sb.append("&apos;");
                lastOut = i;
                break;
            case '\"':
                if (lastOut != i-1) sb.append(s.substring(lastOut+1, i));
                sb.append("&quot;");
                lastOut = i;
                break;
            default:
                // not a special character
            }
        }
        if (lastOut != n-1) sb.append(s.substring(lastOut+1, n));
    }

    public static String unescapeString(final String s) {
        if (s == null) return s;
        int n = s.length();
        int nextAmp = s.indexOf('&', 0);
        if (nextAmp < 0) return s;

        StringBuffer t = new StringBuffer();
        for (int ind = 0; ind < n;) {
            if (nextAmp < 0) {
                t.append(s.subSequence(ind, n));
                ind = n;
                break;
            }
            t.append(s.substring(ind, nextAmp));
            int nextSemi = s.indexOf(';', nextAmp);
            if (nextSemi < 0) {
                t.append(s.subSequence(ind, n));
                ind = n;
                break;
            }
            String esc = s.substring(nextAmp+1, nextSemi);
            if ("amp".equals(esc)) {
                t.append('&');
            }
            else if ("lt".equals(esc)) {
                t.append('<');
            }
            else if ("gt".equals(esc)) {
                t.append('>');
            }
            else if ("apos".equals(esc)) {
                t.append('\'');
            }
            else if ("quot".equals(esc)) {
                t .append('\"');
            }
            else {
                t.append('&');
                t.append(esc);
                t.append(';');
            }
            ind = nextSemi+1;
            nextAmp = s.indexOf('&', ind);
        }
        return t.toString();
    }

    public static String nextTag(Label lbl, Reader r) throws IllegalArgumentException, IOException{
        swallowString(lbl, r, "<");
        return readUntil(lbl, r, ">");
    }
    public static String readUntil(Label lbl, Reader r, String s) throws IllegalArgumentException, IOException {
        return readUntilImpl(lbl, r, s, true);
    }
    public static void skipUntil(Label lbl, Reader r, String s) throws IllegalArgumentException, IOException {
        readUntilImpl(lbl, r, s, false);
    }
    private static String readUntilImpl(Label lbl, Reader r, String s, boolean record) throws IllegalArgumentException, IOException {
        if (s == null || s.length() == 0) return "";
        int sentinalChar = s.charAt(0);

        StringBuffer sb = new StringBuffer();

        while (true) {
            int ch = r.read();
            if (ch == -1)  throw new IOException("Unexpected end of stream");
            if (((char)ch) == sentinalChar) {
                boolean matchesSentinal = true;
                for (int i = 1; i < s.length(); i++) {
                    ch = r.read();
                    if (ch == -1)  throw new IOException("Unexpected end of stream");
                    if (((char)ch) != s.charAt(i)) {
                        matchesSentinal = false;
                        if (record) {
                            sb.append(s.substring(0, i));
                            sb.append((char)ch);
                        }
                        break;
                    }
                }
                if (matchesSentinal) {
                    // we've matched the sentinal
                    return sb.toString();
                }
            }
            else {
                if (record) sb.append((char)ch);
            }
        }
    }
    /**
     * Swallows initial white space, and the initial "<tag>" string
     */
    public static void swallowTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException{
        swallowString(lbl, r, "<");
        swallowString(lbl, r, tag);
        swallowString(lbl, r, ">");
    }
    /**
     * Swallows initial white space, and the initial "</tag>" string
     */
    public static void swallowEndTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        swallowString(lbl, r, "</");
        swallowString(lbl, r, tag);
        swallowString(lbl, r, ">");
    }

    private static void swallowString(Label lbl, Reader r, String s) throws IllegalArgumentException, IOException {
        if (r == null || s == null) {
            throw new IllegalArgumentException("Null arguments");
        }

        int ch = r.read();

        // skip over white space
        while (ch != -1 && Character.isWhitespace((char)ch)) ch = r.read();

        // now go through and swallow the string s
        for (int i = 0; i < s.length(); i++) {
            if (ch == -1) {
                throw new IOException("Unexpected end of file: expecting " + s);
            }
            try {
                if (((char)ch) != s.charAt(i)) {
                    // try finding some more context, for a better error message...
                    StringBuffer received = new StringBuffer();
                    received.append(s.substring(0,i));
                    received.append((char)ch);
                    try {
                        int count = 10;
                        while (count-- > 0) {
                            ch = r.read();
                            received.append((char)ch);
                            if (ch == '>') break;
                        }
                    }
                    finally {
                        throw new IOException("Expecting " + s + " got " + received.toString());
                    }
                }
            }
            catch (StringIndexOutOfBoundsException imposs) { }

            if (i+1 < s.length()) ch = r.read();
        }
    }

    /**
     * Returns everything in s up to the next '<' char
     */
    public static String readSimpleTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        if (r == null || tag == null) {
            throw new IllegalArgumentException("Null arguments");
        }

        swallowString(lbl, r, "<");
        swallowString(lbl, r, tag);
        int ch;
        do {
            ch = r.read();
        } while (ch != -1 && Character.isWhitespace(ch));

        if (ch == '/') {
            // it's an empty tag, e.g. <applause/>
            swallowString(lbl, r, ">");
            return "";
        }
        if (ch != '>') {
            // error!
            throw new IOException("Expecting <" + tag + ">");
        }

        StringBuffer s = new StringBuffer();

        do {
            ch = r.read();
            if (ch != -1 && ch != '<') s.append((char)ch);
        } while (ch != -1 && ch != '<');

        if (ch == -1) {
            throw new IOException("Unexpected end of file");
        }
        swallowString(lbl, r, "/");
        swallowString(lbl, r, tag);
        swallowString(lbl, r, ">");
        return stripTrailingLeadingWhitespace(s.toString());
    }

    /**
     * Returns the value of the next simple tag, interpreted as an integer.
     */
    public static int readSimpleIntTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        String s = readSimpleTag(lbl, r, tag);
        try {
            return Integer.parseInt(s);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Expected an int: '" + s + "'");
        }
    }

    /**
     * Returns the value of the next simple tag, interpreted as a long.
     */
    public static long readSimpleLongTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        String s = readSimpleTag(lbl, r, tag);
        try {
            return Long.parseLong(s);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Expected a long: '" + s + "'");
        }
    }

    /**
     * Returns the value of the next simple tag, interpreted as a boolean.
     */
    public static boolean readSimpleBooleanTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        return stringToBoolean(readSimpleTag(lbl, r, tag));
    }

    public static boolean stringToBoolean(String s) {
        return "true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s) || "y".equalsIgnoreCase(s);
    }

    /**
     * returns true if the next tag is "<tag>". does not consume any characters except whitespace
     */
    public static boolean isNextTag(Label lbl, Reader r, String tag) throws IllegalArgumentException, IOException {
        if (r == null || tag == null) {
            throw new IllegalArgumentException("Null arguments");
        }
        int ch;
        do {
            r.mark(tag.length() + 3);
            ch = r.read();
        } while (ch != -1 && Character.isWhitespace((char)ch));
        if (ch != '<') {
            r.reset();
            return false;
        }

        int tagLength = tag.length();
        for (int i = 0; i < tagLength; i++) {
            ch = r.read();
            if (ch == -1 || ch != tag.charAt(i)) {
                r.reset();
                return false;
            }
        }
        ch = r.read();
        boolean result = (ch == '>');
        r.reset();
        return result;
    }

    public static int[] invertPermutation(Label lbl, Label lbl2, int[] p) {
        if (p == null) return p;
        int[] q = new int[p.length];
        for (int i = 0; i < p.length; i++) {
            try {
                q[p[i]] = i;
            }
            catch (ArrayIndexOutOfBoundsException imposs) { }
        }
        return q.clone();
    }

    /**
     * Convert a byte array into a string suitable for an xml message.
     */
    public static String bytesToString(Label lbl, byte[] bs) {
        if (bs == null) return null;

        return Base64.encodeBytes(bs);
    }

    /**
     * Convert a byte array into a string suitable for an xml message.
     */
    public static String constBytesToString(Label lbl, byte  [] bs) {
        return bytesToString(lbl, bs);
    }

    /**
     * Convert string produced by bytesToString back into a byte array.
     */
    public static byte[] stringToBytes(Label lbl, String s) {
        if (s == null) return null;
        return Base64.decode(s);
    }

    /**
     * Convert string produced by bytesToString back into a byte array.
     */
    public static byte[] stringToConstBytes(Label lbl, String s) {
        return stringToBytes(lbl, s);
    }

    /**
     * Check that two byte arrays are equal.
     */
    public static boolean equals(Label lbl, byte[] a, byte[] b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            try {
                if (a[i] != b[i]) return false;
            }
            catch (ArrayIndexOutOfBoundsException imposs) { }
        }
        return true;
    }
    public static boolean equals(Label lbl, byte[] a, byte[] b, boolean constArrays) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            try {
                if (a[i] != b[i]) return false;
            }
            catch (ArrayIndexOutOfBoundsException imposs) { }
        }
        return true;
    }
}
