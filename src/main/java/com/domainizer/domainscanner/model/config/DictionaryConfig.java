package com.domainizer.domainscanner.model.config;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
public class DictionaryConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_dictionary_config")
    private long id;

    @Column(name = "dictionary_file")
    @Size(min = 3, max = 70)
    private String dictionaryFile;

    public DictionaryConfig() {
    }

    public DictionaryConfig(long id, String dictionaryFile) {
        this.id = id;
        this.dictionaryFile = dictionaryFile;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getDictionaryFile() {
        return dictionaryFile;
    }

    public void setDictionaryFile(String dictionaryFile) {
        this.dictionaryFile = dictionaryFile;
    }
}
