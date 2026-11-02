package com.android.insecurebankv2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import android.widget.Toast;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import org.json.JSONException;
import org.json.JSONObject;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.marcohc.toasteroid.Toasteroid;

/*
The page that allows the user to transfer an amount between two accounts
@author Dinesh Shetty
*/
public class DoTransfer extends Activity {

	String result;
	String passNormalized;
	String usernameBase64ByteString;
	BufferedReader reader;
	EditText from;
	EditText to;
	EditText amount;
	EditText phoneNumber;
	String number = "5554";
	Button getAccounts;
	Button transfer;
	String acc1, acc2;
	HttpResponse responseBody;
	JSONObject jsonObject;
	InputStream in ;
	String serverip = "";
	String serverport = "";
	String protocol = "http://";
	Button button1;
	SharedPreferences serverDetails;
	public static final String MYPREFS2 = "mySharedPreferences";
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_do_transfer);

		// Get Server details from Shared Preference file.
		serverDetails = PreferenceManager.getDefaultSharedPreferences(this);
		serverip = serverDetails.getString("serverip", null);
		serverport = serverDetails.getString("serverport", null);

		// Handle the transfer functionality
		transfer = (Button) findViewById(R.id.button_Transfer);
		transfer.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				from = (EditText) findViewById(R.id.editText_from);
				to = (EditText) findViewById(R.id.editText_to);
				new RequestDoTransferTask().execute("username");
			}
		});

		button1 = (Button) findViewById(R.id.button_CreateUser);
		button1.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				new RequestDoGets2().execute("username");
			}
		});

		//	"Pick Beneficiary" opens the beneficiary manager in picker mode so a
		//	registered beneficiary can be used as the transfer target.
		Button pickBeneficiary = (Button) findViewById(R.id.button_PickBeneficiary);
		pickBeneficiary.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				Intent i = new Intent(getApplicationContext(), BeneficiaryActivity.class);
				i.putExtra("uname", BankSession.getUsername(DoTransfer.this));
				i.putExtra(BeneficiaryActivity.EXTRA_SELECT_MODE, true);
				startActivityForResult(i, PICK_BENEFICIARY_REQUEST);
			}
		});
	}

	private static final int PICK_BENEFICIARY_REQUEST = 1001;

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		if (requestCode != PICK_BENEFICIARY_REQUEST || data == null) {
			return;
		}
		String account = data.getStringExtra(BeneficiaryActivity.EXTRA_SELECTED_ACCOUNT);
		String person = data.getStringExtra(BeneficiaryActivity.EXTRA_SELECTED_NAME);
		if (account == null) {
			return;
		}
		EditText toField = (EditText) findViewById(R.id.editText_to);
		toField.setText(account);
		Toasteroid.show(this, "Beneficiary applied", Toasteroid.STYLES.SUCCESS,
				Toasteroid.LENGTH_SHORT);
	}

	public class RequestDoTransferTask extends AsyncTask < String, String, String > {

		public void AsyncHttpTransferPost(String string) {
		}

		@Override
		protected String doInBackground(String...params) {
			String str = "";
			str = "dinesh";
			HttpClient httpclient = new DefaultHttpClient();
			HttpPost httppost = new HttpPost(protocol + serverip + ":" + serverport + "/dotransfer");
			SharedPreferences settings = getSharedPreferences(MYPREFS2, 0);
			final String username = settings.getString("EncryptedUsername", null);
			byte[] usernameBase64Byte = Base64.decode(username, Base64.DEFAULT);
			final String password = settings.getString("superSecurePassword", null);
			try {
				passNormalized = getNormalizedPassword(password);
			} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e1) {
				e1.printStackTrace();
			}
			List < NameValuePair > nameValuePairs = new ArrayList < NameValuePair > (5);
			nameValuePairs.add(new BasicNameValuePair("username", usernameBase64ByteString));
			nameValuePairs.add(new BasicNameValuePair("password", passNormalized));
			from = (EditText) findViewById(R.id.editText_from);
			to = (EditText) findViewById(R.id.editText_to);
			amount = (EditText) findViewById(R.id.editText_amount);
			nameValuePairs.add(new BasicNameValuePair("from_acc", from.getText().toString()));
			nameValuePairs.add(new BasicNameValuePair("to_acc", to.getText().toString()));
			nameValuePairs.add(new BasicNameValuePair("amount", amount.getText().toString()));
			try {
				httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			try {
				//	Stores the HTTP response of the transaction activity
				responseBody = httpclient.execute(httppost);
				// RASP ME-10: network event for /dotransfer
				Rasp.network(serverip, serverport, "http", "POST", "/dotransfer",
						responseBody.getStatusLine().getStatusCode(),
						responseBody.getEntity().getContentLength(), "DoTransfer");
			} catch (IOException e1) {
				Rasp.network(serverip, serverport, "http", "POST", "/dotransfer", 0, 0, "DoTransfer");
				e1.printStackTrace();
			}

			try { in = responseBody.getEntity().getContent();
			} catch (IllegalStateException | IOException e1) {
				e1.printStackTrace();
			}
			try {
				result = convertStreamToString( in );
			} catch (IOException e) {
				e.printStackTrace();
			}
			result = result.replace("\n", "");
			runOnUiThread(new Runnable() {

				@Override
				public void run() {
					AsyncHttpTransferPost("result");
					if (result != null) {
						if (result.indexOf("Success") != -1) {
							Toasteroid.show(DoTransfer.this, "Transfer Successful!!", Toasteroid.STYLES.SUCCESS, Toasteroid.LENGTH_SHORT);

							try {
								jsonObject = new JSONObject(result);
								acc1 = jsonObject.getString("from");
								acc2 = jsonObject.getString("to");
								System.out.println("Message:" + jsonObject.getString("message") + " From:" + from.getText().toString() + " To:" + to.getText().toString() + " Amount:" + amount.getText().toString());
								final String status = new String("\nMessage:" + "Success" + " From:" + from.getText().toString() + " To:" + to.getText().toString() + " Amount:" + amount.getText().toString() + "\n");
								try {
									String MYFILE = Environment.getExternalStorageDirectory() + "/Statements_" + usernameBase64ByteString + ".html";
									BufferedWriter out2 = new BufferedWriter(new FileWriter(MYFILE, true));
									out2.write(status);
									out2.write("<hr>");
									out2.close();
									// RASP ME-03: file write
									Rasp.file(MYFILE, "WRITE", true, "DoTransfer");
								} catch (IOException e) {
									e.toString();
								}
							} catch (JSONException e) {
								e.printStackTrace();
							}
						} else {
							Toasteroid.show(DoTransfer.this, "Transfer Failed!!", Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);

							System.out.println("Message:" + "Failure" + " From:" + from.getText().toString() + " To:" + to.getText().toString() + " Amount:" + amount.getText().toString());
							final String status = new String("\nMessage:" + "Failure" + " From:" + from.getText().toString() + " To:" + to.getText().toString() + " Amount:" + amount.getText().toString() + "\n");
							String MYFILE = Environment.getExternalStorageDirectory() + "/Statements_" + usernameBase64ByteString + ".html";
							try {
								BufferedWriter out2 = new BufferedWriter(new FileWriter(MYFILE, true));
								out2.write(status);
								out2.write("<hr>");
								out2.close();
								// RASP ME-03: file write
								Rasp.file(MYFILE, "WRITE", true, "DoTransfer");
							} catch (IOException e) {
								Rasp.file(MYFILE, "WRITE", false, "DoTransfer");
							}
						}
					}
				}

			});
			return str;
		}

		@Override
		protected void onPostExecute(String result) {}

		protected void onProgressUpdate(String...progress) {}
	}

	public class RequestDoGets2 extends AsyncTask < String, String, String > {

		public void AsyncHttpPost(String string) {
		}

		@Override
		public String doInBackground(String...params) {
			String str = "";
			str = "dinesh";
			HttpClient httpclient = new DefaultHttpClient();

			HttpPost httppost = new HttpPost(protocol + serverip + ":" + serverport + "/getaccounts");
			SharedPreferences settings = getSharedPreferences(MYPREFS2, 0);
			final String username = settings.getString("EncryptedUsername", null);
			byte[] usernameBase64Byte = Base64.decode(username, Base64.DEFAULT);

			try {
				usernameBase64ByteString = new String(usernameBase64Byte, "UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}

			final String password = settings.getString("superSecurePassword", null);
			try {
				passNormalized = getNormalizedPassword(password);
			} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e1) {
				e1.printStackTrace();
			}
			List < NameValuePair > nameValuePairs = new ArrayList < NameValuePair > (2);
			nameValuePairs.add(new BasicNameValuePair("username", usernameBase64ByteString));
			nameValuePairs.add(new BasicNameValuePair("password", passNormalized));
			try {
				httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			try {
				//	Stores the HTTP response of the get account numbers activity
				responseBody = httpclient.execute(httppost);
				// RASP ME-10: network event for /getaccounts
				Rasp.network(serverip, serverport, "http", "POST", "/getaccounts",
						responseBody.getStatusLine().getStatusCode(),
						responseBody.getEntity().getContentLength(), "DoTransfer");
			} catch (IOException e2) {
				Rasp.network(serverip, serverport, "http", "POST", "/getaccounts", 0, 0, "DoTransfer");
				e2.printStackTrace();
			}

			try { in = responseBody.getEntity().getContent();
			} catch (IllegalStateException | IOException e1) {
				e1.printStackTrace();
			}

			try {
				result = convertStreamToString( in );
			} catch (IOException e) {
				e.printStackTrace();
			}
			result = result.replace("\n", "");
			if (result != null) {
				if (result.indexOf("Correct") != -1) {
					try {
						jsonObject = new JSONObject(result);
						acc1 = jsonObject.getString("from");
						acc2 = jsonObject.getString("to");
					} catch (JSONException e) {
						e.printStackTrace();
					}
				}
			}

			runOnUiThread(new Runnable() {

				@Override
				public void run() {
					AsyncHttpPost("result");
					from = (EditText) findViewById(R.id.editText_from);
					to = (EditText) findViewById(R.id.editText_to);
					from.setText(acc1);
					to.setText(acc2);
				}
			});
			return str;
		}

		@Override
		public void onPostExecute(String result) {}

		public void onProgressUpdate(String...progress) {}
	}

	private String getNormalizedPassword(String password) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		CryptoClass crypt = new CryptoClass();
		return crypt.aesDeccryptedString(password);
	}


	public String convertStreamToString(InputStream in ) throws IOException {
		try {
			reader = new BufferedReader(new InputStreamReader( in , "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		StringBuilder sb = new StringBuilder();
		String line = null;
		while ((line = reader.readLine()) != null) {
			sb.append(line + "\n");
		} in .close();
		return sb.toString();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		int id = item.getItemId();

		switch (item.getItemId()) {
			case android.R.id.home:
				this.finish();
				return true;
			case R.id.action_settings:
				callPreferences();
				return true;

			case R.id.action_exit:
				Intent i = new Intent(getBaseContext(), LoginActivity.class);
				i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
				startActivity(i);
				return true;

			default:
				return super.onOptionsItemSelected(item);
		}

	}

	public void callPreferences() {
		Intent i = new Intent(this, FilePrefActivity.class);
		startActivity(i);
	}
}
