package elgamal;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Controller extends Window {
    public TextField keyG = new TextField();
    public TextField keyH = new TextField();
    public TextField modN = new TextField();
    public TextField keyA = new TextField();

    public TextArea signatureArea = new TextArea();
    public TextArea publicText = new TextArea();

    public Button signButton = new Button();
    public Button verifyButton = new Button();
    public Button generateButton = new Button();
    public Button signFileButton = new Button();
    public Button verifyFile = new Button();

    public Label fileWithPublicText = new Label();
    public Label signFileLabel = new Label();
    public Label signLabel = new Label();
    public Label verifyLabel = new Label();

    private final ElGamal elGamal = new ElGamal();

    final FileChooser fileChooser = new FileChooser();

    public Controller() throws NoSuchAlgorithmException {}

    public void initialize() {
        publicText.setWrapText(true);
        signatureArea.setWrapText(true);
    }

    public void generate() {
        elGamal.GenerujKlucz();
        keyA.setText(elGamal.getA().toString(16));
        keyH.setText(elGamal.getH().toString(16));
        modN.setText(elGamal.getNn1().toString(16));
        keyG.setText(elGamal.getG().toString(16));
    }

    public void signText() {
        if(keyA.getText().equals("") || keyG.getText().equals("") || keyH.getText().equals("") || modN.getText().equals("")) {
            generate();
        }
        BigInteger[] result = elGamal.podpis(publicText.getText().getBytes());
        signatureArea.setText(result[0].toString(16) + "\n" +  result[1].toString(16));
    }

    public void verifyText() {
        if(keyA.getText().equals("") || keyG.getText().equals("") || keyH.getText().equals("") || modN.getText().equals("")) {
            generate();
        }
        BigInteger[] signature = Arrays.stream(signatureArea.getText()
                                .split("\n"))
                                .map(ElGamal::hexToBytes)
                                .map(BigInteger::new)
                                .toArray(BigInteger[]::new);
        if (elGamal.weryfikacja(publicText.getText().getBytes(), signature)) {
            Alert alert = new Alert(Alert.AlertType.NONE, "Zweryfikowano poprawnie!", ButtonType.OK);
            alert.setTitle("Weryfikacja");
            alert.setResizable(false);
            alert.showAndWait();
        } else {
            Alert alert = new Alert(Alert.AlertType.NONE, "Zweryfikowano niepoprawnie!", ButtonType.OK);
            alert.setTitle("Weryfikacja");
            alert.setResizable(false);
            alert.showAndWait();
        }
    }

    public void signFile() {
        try {
            if(keyA.getText().equals("") || keyG.getText().equals("") || keyH.getText().equals("") || modN.getText().equals("")) {
                generate();
            }
            fileChooser.setTitle("Wybierz plik do podpisania");
            File fileToSign = fileChooser.showOpenDialog(this);
            BigInteger[] signNumbers = elGamal.podpis(Files.readAllBytes(fileToSign.getAbsoluteFile().toPath()));
            fileChooser.setTitle("Zapisz podpis do pliku");
            File signFile = fileChooser.showSaveDialog(this);
            fileWithPublicText.setText("Otworzono do podpisu: " + fileToSign.getName());
            try (FileWriter fos = new FileWriter(signFile, true)) {
            fos.write(signNumbers[0].toString(16));
            fos.write('\n');
            fos.write(signNumbers[1].toString(16));
            }
            signLabel.setText("Podpis zapisano do: " + signFile.getName());
        } catch (NullPointerException | IOException e) {
            Alert alert = new Alert(Alert.AlertType.NONE, "Nie wybrano pliku!", ButtonType.OK);
            alert.setTitle("Błąd");
            alert.setResizable(false);
            alert.showAndWait();
        }
    }

    public void verifyFile() {
        try {
            if(keyA.getText().equals("") || keyG.getText().equals("") || keyH.getText().equals("") || modN.getText().equals("")) {
                generate();
            }
            fileChooser.setTitle("Wybierz plik, który był podpisany");
            File signedFile = fileChooser.showOpenDialog(this);
            fileChooser.setTitle("Wybierz plik z podpisem");
            File fileWithSign = fileChooser.showOpenDialog(this);
            BigInteger[] signature = Arrays.stream(new String(Files.readAllBytes(fileWithSign.toPath()))
                    .split("\n"))
                    .map(ElGamal::hexToBytes)
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);
            if (elGamal.weryfikacja(Files.readAllBytes(signedFile.getAbsoluteFile().toPath()), signature)) {
                Alert alert = new Alert(Alert.AlertType.NONE, "Zweryfikowano poprawnie", ButtonType.OK);
                alert.setTitle("Weryfikacja");
                alert.setResizable(false);
                alert.showAndWait();
            } else {
                Alert alert = new Alert(Alert.AlertType.NONE, "Zweryfikowano niepoprawnie", ButtonType.OK);
                alert.setTitle("Weryfikacja");
                alert.setResizable(false);
                alert.showAndWait();
            }
            signFileLabel.setText("Otworzono podpisany plik: " + signedFile.getName());
            verifyLabel.setText("Do weryfikacji podpisu otworzono: " + fileWithSign.getName());
        } catch (NullPointerException | FileNotFoundException e) {
            Alert alert = new Alert(Alert.AlertType.NONE, "Nie wybrano pliku!", ButtonType.OK);
            alert.setTitle("Błąd");
            alert.setResizable(false);
            alert.showAndWait();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}