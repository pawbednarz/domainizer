package com.domainizer.util;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UtilsTest {

    private static final String fileData = "test String data";
    private static final String filename = "testFilename.txt";
    private static final String dictionaryDirectory = "dictionaryFiles";

    @BeforeAll
    public static void createTestFile() {
        Utils.saveDictionaryFileToDisk(fileData, filename);
    }

    @AfterAll
    public static void deleteTestFile() {
        File f = new File(dictionaryDirectory + "/" + filename);
        f.delete();
    }

    @Test
    void testSaveDictionaryFileToDisk_isFileCreated() {
        File dictionaryFile = new File(dictionaryDirectory + "/" + filename);
        assertTrue(dictionaryFile.exists() && dictionaryFile.isFile());
    }

    @Test
    void testSaveDictionaryFileToDisk_isFileContentCorrect() throws FileNotFoundException {
        File dictionaryFile = new File(dictionaryDirectory + "/" + filename);
        Scanner reader = new Scanner(dictionaryFile);
        StringBuilder data = new StringBuilder();
        while (reader.hasNextLine()) {
            data.append(reader.nextLine());
        }
        reader.close();
        assertEquals(fileData, data.toString());
    }
}