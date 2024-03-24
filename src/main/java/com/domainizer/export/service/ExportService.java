package com.domainizer.export.service;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class ExportService {

    final float CELL_HEIGHT = 25;

    DomainRepository domainRepository;

    @Autowired
    public ExportService(DomainRepository domainRepository) {
        this.domainRepository = domainRepository;
    }

    public String exportDomainsToTxt(Long runScanId) {
        return domainRepository
                .findAllByRunScanId(runScanId)
                .stream()
                .map(Domain::getName)
                .collect(Collectors.joining("\n"));
    }

    public ByteArrayInputStream exportDomainsToPdf(Long runScanId) {
        List<Domain> domains = domainRepository.findAllByRunScanId(runScanId);

        Document document = new Document();
        document.addTitle("Subdomains export for run scan ID " + runScanId);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfWriter.getInstance(document, out);
            document.open();
            PdfPTable table = new PdfPTable(2);
            table.setWidthPercentage(100);
//            table.setWidths(new int[]{2, 1, 2});
            addTableHeader(table, new String[]{"Domain", "IP address", "Discovery source"});
            Font font = FontFactory.getFont(FontFactory.TIMES, 12, BaseColor.BLACK);
            for (Domain domain : domains) {
                addRows(table, domain.getName(), domain.getIpAddress());
            }
            document.add(table);
            document.close();
            return new ByteArrayInputStream(out.toByteArray());
        } catch (DocumentException e) {
            throw new RuntimeException(e);
        }
    }

    public String exportDomainsToCsv(Long runScanId) {
        StringBuilder sb = new StringBuilder("Domain,IP address");
        List<Domain> domains = domainRepository.findAllByRunScanId(runScanId);
        for (Domain d : domains) {
            sb.append("\n");
            sb.append(d.getName());
            sb.append(",");
            sb.append(d.getIpAddress());
        }
        return sb.toString();
    }

    private void addTableHeader(PdfPTable table, String[] headerValues) {
        Stream.of(headerValues)
                .forEach(columnTitle -> {
                    PdfPCell header = new PdfPCell();
                    header.setBackgroundColor(BaseColor.LIGHT_GRAY);
                    header.setBorderWidth(2);
                    header.setPhrase(new Phrase(columnTitle));
                    header.setFixedHeight(CELL_HEIGHT);
                    table.addCell(header);
                });
    }

    private void addRows(PdfPTable table, String domain, String ip) {
        PdfPCell cell = new PdfPCell();
        cell.setFixedHeight(CELL_HEIGHT);
        cell.addElement(new Phrase(domain));
        cell.setVerticalAlignment(Element.ALIGN_CENTER);
        table.addCell(cell);

        cell = new PdfPCell();
        cell.setFixedHeight(CELL_HEIGHT);
        cell.addElement(new Phrase(ip));
        cell.setVerticalAlignment(Element.ALIGN_CENTER);
        table.addCell(cell);
    }
}
