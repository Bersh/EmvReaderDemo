package com.example.test;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Vibrator;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.util.Arrays;

public class MyActivity extends Activity {

    private NfcAdapter nfcAdapter;
    private static final String LOG_TAG = "NFC_TEST_READER";
    private TextView txtCardNumber;
    private TextView txtExpDate;
    private TextView txtPleaseScan;
    private TextView txtHolderName;
    private View layoutExpDate;
    private View layoutCardNumber;
    private View layoutHolderName;
    final int cardNumberLength = 16;
    final boolean IS_DEBUG = true;
    private Vibrator vibrator;

    final byte[] masterCardRid = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x04};
    final byte[] masterCardAid = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10};

    final byte[] visaRid = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x03};
    final byte[] visaAid = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);

        txtCardNumber = (TextView) findViewById(R.id.txt_card_number);
        txtPleaseScan = (TextView) findViewById(R.id.txt_message);
        txtExpDate = (TextView) findViewById(R.id.txt_exp_date);
        layoutExpDate = findViewById(R.id.layout_exp_date);
        layoutCardNumber = findViewById(R.id.layout_card_number);
        layoutHolderName = findViewById(R.id.layout_holder_name);
        txtHolderName = (TextView) findViewById(R.id.txt_holder_name);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null && !nfcAdapter.isEnabled()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setMessage(getString(R.string.msg_nfc_disabled));
            builder.setPositiveButton(getString(android.R.string.yes), new DialogInterface.OnClickListener() {

                @Override
                public void onClick(DialogInterface dialog, int which) {
                    startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
                }
            });

            builder.setCancelable(false);
            builder.show();
        } else {
            Intent nfcIntent = new Intent(this, MyActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
            PendingIntent pi = PendingIntent.getActivity(this, 0, nfcIntent, PendingIntent.FLAG_UPDATE_CURRENT);
            IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);

            nfcAdapter.enableForegroundDispatch(this, pi, new IntentFilter[]{tagDetected}, null);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag == null) {
                return;
            }

            final IsoDep isoDep = IsoDep.get(tag);
            NfcA nfcA = NfcA.get(tag);
            if (nfcA != null && isoDep != null) {
                vibrator.vibrate(500);
                txtPleaseScan.setVisibility(View.GONE);
                getDataFromTag(isoDep);
            } else {
                showUnsupportedCardTypeMessage();
            }

        }
    }

    private void getDataFromTag(IsoDep isoDep) {
        try {
            isoDep.connect();
            byte[] result;
            Log.d(LOG_TAG, "Historical Bytes:");
            printResultToLog(isoDep.getHistoricalBytes());
            Log.d(LOG_TAG, "-----------------------------------------------------------------------------");

            if (IS_DEBUG) { //select all applications command for debug
                byte[] command = {0x00, (byte) 0xA4, 0x04, 0x00};
//                byte[] command = {0x00, (byte) 0xA4, 0x04, 0x00, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44,
//                        0x46, 0x30, 0x31, 0x00};
                result = executeCommand(isoDep, command);
                byte[] rid = Arrays.copyOfRange(result, 4, 9);
                Log.d(LOG_TAG, "RID: " + getHexStringFromBytesArray(rid));
            }

            if (!selectApplication(isoDep, masterCardAid) && !selectApplication(isoDep, visaAid)) {
                showUnsupportedCardTypeMessage();
                return;
            }

            byte[] command2 = { // Get the Application File Locator (AFL)
                    (byte) 0x80, (byte) 0xA8, 0x00, 0x00, 0x02, (byte) 0x83, 0x00};
            result = executeCommand(isoDep, command2);

            // AIP = 82 02
            // SFI1 = 19
            // SFI2 = 08
            // SFI3= 10

            // 0x14 = 0x10 + 0x04
            // 0x0C = 0x08 + 0x04
            byte[] command3 = {
                    0x00, (byte) 0xB2, (byte) 0x01, (byte) 0x0C, (byte) 0x00};
            result = executeCommand(isoDep, command3);
            String tmpStringResult = new String(result);
            Log.d(LOG_TAG, "String result: " + tmpStringResult);
            int nameStartIndex = tmpStringResult.indexOf("^") + 1;
            int nameEndIndex = tmpStringResult.indexOf("^", nameStartIndex);
            String holderName = tmpStringResult.substring(nameStartIndex, nameEndIndex);
            String tmpExpDateString = tmpStringResult.substring(nameEndIndex + 1, nameEndIndex + 5);
            String expDate = getExpDateString(tmpExpDateString);

            byte[] command4 = {
                    0x00, (byte) 0xB2, (byte) 0x01, (byte) 0x14, (byte) 0x00};
            result = executeCommand(isoDep, command4);

            tmpStringResult = new String(result);
            Log.d(LOG_TAG, "String result: " + tmpStringResult);
            String cardNumber = getCardNumberString(result); //card number will be obtained from hex data

            layoutCardNumber.setVisibility(View.VISIBLE);
            layoutExpDate.setVisibility(View.VISIBLE);
            layoutHolderName.setVisibility(View.VISIBLE);
            txtCardNumber.setText(formatCardNumber(cardNumber));
            txtExpDate.setText(expDate);
            txtHolderName.setText(holderName);
            isoDep.close();
        } catch (IOException e) {
            e.printStackTrace();
            Log.e(LOG_TAG, "", e);
            Toast.makeText(MyActivity.this, e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void showUnsupportedCardTypeMessage() {
        txtPleaseScan.setVisibility(View.VISIBLE);
        txtPleaseScan.setText(getString(R.string.err_unsupported_card));
    }

    /**
     * Execute SELECT command for given AID
     *
     * @param isoDep IsoDep instance to execute command
     * @param aid    application id
     * @return true if success (status 90 00) false otherwise
     */
    private boolean selectApplication(IsoDep isoDep, byte[] aid) {
        boolean success = false;
        byte[] result;
        byte[] selectCommandHeader = {
                (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, // select command
                (byte) 0x07 // aid length in bytes
        };

        byte[] selectApplicationCommand = new byte[selectCommandHeader.length + aid.length];

        System.arraycopy(selectCommandHeader, 0, selectApplicationCommand, 0, selectCommandHeader.length);
        System.arraycopy(aid, 0, selectApplicationCommand, selectCommandHeader.length, masterCardAid.length);

        try {
            result = getStatusFormResult(executeCommand(isoDep, selectApplicationCommand));
            success = result[0] == (byte) 0x90 && result[1] == 0x00;
        } catch (IOException e) {
            success = false;
            Log.e(LOG_TAG, "Error while selecting application", e);
        }
        return success;
    }

    private String getCardNumberString(byte[] fullResponse) {
        String resultHexString = getHexStringFromBytesArray(fullResponse).toLowerCase();
        int numberEnd = resultHexString.indexOf("d1");
        return resultHexString.substring(numberEnd - 16 - 8, numberEnd).replaceAll("\\s+", "");
    }

    private String getExpDateString(String tmpExpDateString) {
        String expDateMonth = tmpExpDateString.substring(2, 4);
        String expDateYear = tmpExpDateString.substring(0, 2);
        return expDateMonth + "/" + expDateYear;
    }

    /**
     * Insert spaces into card number string
     *
     * @param cardNumberString card number without spaces
     * @return card number with spaces
     */
    private String formatCardNumber(String cardNumberString) {
        StringBuilder str = new StringBuilder(cardNumberString);
        int index = cardNumberString.length() - 4;
        while (index > 0) {
            str.insert(index, " ");
            index -= 4;
        }
        return str.toString();
    }

    /**
     * Returns SW1 and SW2 bytes from full response
     *
     * @param fullResult full card response bytes
     * @return two bytes: SW1 and SW2
     */
    private byte[] getStatusFormResult(byte[] fullResult) {
        return Arrays.copyOfRange(fullResult, fullResult.length - 2, fullResult.length);
    }

    /**
     * Executes given IsoDep command
     *
     * @param isoDep  IsoDep instance to execute command
     * @param command command bytes
     * @return full card response
     * @throws IOException if android.nfc.tech.IsoDep#transceive(byte[]) fails
     */
    private byte[] executeCommand(IsoDep isoDep, byte[] command) throws IOException {
        Log.d(LOG_TAG, "Command " + getHexStringFromBytesArray(command));
        byte[] result = isoDep.transceive(command);
        if (result != null && IS_DEBUG) {
            byte[] status = Arrays.copyOfRange(result, result.length - 2, result.length);
            Log.d(LOG_TAG, "Sataus: " + getHexStringFromBytesArray(status));
            printResultToLog(result);
            Log.d(LOG_TAG, "-----------------------------------------------------------------------------");
        }
        return result;
    }

    /**
     * Format and print result to log
     *
     * @param result card responce
     * @return printed string
     */
    private String printResultToLog(byte[] result) {
        if (result != null) {
            String resultString = getHexStringFromBytesArray(result);
            Log.d(LOG_TAG, "Result: " + resultString);
            return resultString;
        } else {
            return "";
        }
    }

    /**
     * Converts bytes array to hex string
     *
     * @param array initial array
     * @return hex string from given array
     */
    private String getHexStringFromBytesArray(byte[] array) {
        StringBuilder sb = new StringBuilder(array.length == 0 ? "Empty string" : "");
        for (byte b : array) {
            sb.append(String.format("%02x", b));
            sb.append(" ");
        }
        return sb.toString();
    }
}
