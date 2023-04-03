package kryptografia;

import javafx.event.ActionEvent;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InputController implements Initializable {

    public TextField keyTextField;
    public Button applyKeyButton;
    public Button randomKeyButton;
    public Button decryptButton;
    public Button encryptButton;
    public TextArea decipheredDataField;
    public TextArea encryptedDataField;
    public TextArea rawDataField;
    public TextArea rawDataAsBytesArea;
    public TextArea decipheredAsBytesField;

    AES aes;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        keyTextField.textProperty().addListener((observableValue, oldValue, newValue) -> {
            Pattern p = Pattern.compile("^[a-fA-F0-9]{32}$");
            Matcher m = p.matcher(keyTextField.getText());
            boolean b = m.matches();
            applyKeyButton.setDisable(!b);
        });
    }

    public void createAES(ActionEvent actionEvent) throws Exception {
        byte[] key = aes.hexStringToByteArray(keyTextField.getText());
        aes = new AES(key);
        encryptButton.setDisable(false);
        decryptButton.setDisable(false);
    }

    public void generateRandomKey(ActionEvent actionEvent) {
        String literals = "ABCDEF09876543210";
        Random random = new Random();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            builder.append(literals.charAt(random.nextInt(literals.length())));
        }
        keyTextField.textProperty().set(builder.toString());
    }

    public void encryptText(ActionEvent actionEvent) {

        rawDataAsBytesArea.setText(aes.bytesToHex(rawDataField.getText().getBytes(StandardCharsets.UTF_8)));
        byte[] encoded = aes.encode(rawDataField.getText().getBytes(StandardCharsets.UTF_8));

        encryptedDataField.setText(aes.bytesToHex(encoded));
    }


    public synchronized void decryptText(ActionEvent actionEvent) {
        byte[] toDecrypt = aes.hexStringToByteArray(encryptedDataField.getText());
        byte[] decrypted = aes.decode(toDecrypt);
        String hex = aes.bytesToHex(decrypted);
        decipheredAsBytesField.setText(hex);
        byte[] bytes = new byte[0];
        try {
            bytes = Hex.decodeHex(hex.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        decipheredDataField.setText(new String(bytes, StandardCharsets.UTF_8));
    }

    public void chooseFileAndEncrypt(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(new Stage());
        try {
            byte[] fileBytes = FileUtils.readFileToByteArray(selectedFile);
            byte[] encodedBytes = aes.encode(fileBytes);
            File destination = fileChooser.showSaveDialog(new Stage());
            FileUtils.writeByteArrayToFile(destination, encodedBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void chooseFileAndDecrypt(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(new Stage());
        try {
            byte[] fileBytes = FileUtils.readFileToByteArray(selectedFile);
            byte[] decodedBytes = aes.decode(fileBytes);
            File destination = fileChooser.showSaveDialog(new Stage());
            FileUtils.writeByteArrayToFile(destination, decodedBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
