package com.android.insecurebankv2;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.GridView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import com.marcohc.toasteroid.Toasteroid;


/*
The page that allows gives the user below functionalities
Transfer: Module that allows transfer of amount between two accounts
View Statement: Module that allows the user to view transaction history for the logged in user
Change Password:  Module that allows the logged in user to change the password

The nine destinations are laid out as a 2 column GridView instead of the original stack of
full width rows, so the whole hub fits on one screen. The destination list, the order, the
RaspEvent.NAVIGATE "to=" values and the intents themselves are unchanged, so the recorded
event traces are identical to the ones the research dataset was built from.
@author Dinesh Shetty
*/
public class PostLogin extends Activity {
	//	The GridView holding the nine feature tiles
	GridView dashboard_grid;
    //  The Textview that handles the root status display
    TextView root_status;
	//	The Button that handles the logout action
	Button logout_button;
	String uname;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_post_login);
		Intent intent = getIntent();
		uname = intent.getStringExtra("uname");

        root_status =(TextView) findViewById(R.id.rootStatus);
        //  Display root status
        showRootStatus();
        //	Display emulator status
        checkEmulatorStatus();

		//	IntelliRASP research - the six added features of this FYP build plus the three
		//	pre-existing ones, all reached through the same grid.
		final List<Tile> tiles = buildTiles();
		dashboard_grid = (GridView) findViewById(R.id.dashboard_grid);
		dashboard_grid.setAdapter(new DashboardAdapter(this, tiles));
		dashboard_grid.setOnItemClickListener(new AdapterView.OnItemClickListener() {

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				openTile(tiles.get(position));
			}
		});

		logout_button = (Button) findViewById(R.id.button_Logout);
		logout_button.setOnClickListener(new View.OnClickListener() {

			@Override
			public void onClick(View v) {
				// TODO Auto-generated method stub
				logout();
			}
		});
	}

	/*
	One destination on the dashboard.

	`tag` is what goes into the RaspEvent.NAVIGATE detail as "to=" and must keep matching the
	value the original listeners emitted, because the ML pipeline keys off it. `passUsername`
	is false only for DoTransfer, which the original code deliberately started without the
	"uname" extra; that quirk is preserved here rather than quietly corrected.
	*/
	private static final class Tile {
		final String label;
		final Class<?> target;
		final String tag;
		final boolean passUsername;

		Tile(String label, Class<?> target, String tag, boolean passUsername) {
			this.label = label;
			this.target = target;
			this.tag = tag;
			this.passUsername = passUsername;
		}
	}

	/*
	The nine entries, in the order the original layout listed them.
	*/
	private static List<Tile> buildTiles() {
		List<Tile> tiles = new ArrayList<Tile>(9);
		tiles.add(new Tile("Transfer", DoTransfer.class, "DoTransfer", false));
		tiles.add(new Tile("View Statement", ViewStatement.class, "ViewStatement", true));
		tiles.add(new Tile("Change Password", ChangePassword.class, "ChangePassword", true));
		tiles.add(new Tile("Account Details", AccountDetailsActivity.class, "AccountDetails", true));
		tiles.add(new Tile("Transaction History", TransactionHistoryActivity.class, "TransactionHistory", true));
		tiles.add(new Tile("Beneficiaries", BeneficiaryActivity.class, "Beneficiary", true));
		tiles.add(new Tile("Bill Payment", BillPaymentActivity.class, "BillPayment", true));
		tiles.add(new Tile("Profile", ProfileActivity.class, "Profile", true));
		tiles.add(new Tile("Deposit Money", DepositActivity.class, "Deposit", true));
		return tiles;
	}

	/*
	Opens one of the dashboard's screens and records the navigation event.
	*/
	private void openTile(Tile tile) {
		RaspEvent.ok(RaspEvent.NAVIGATE, "PostLogin", uname, RaspEvent.newOpId(), "to=" + tile.tag);
		Intent i = new Intent(getApplicationContext(), tile.target);
		if (tile.passUsername) {
			i.putExtra("uname", uname);
		}
		startActivity(i);
	}

	/*
	Binds the tile labels into the grid. The cells are identical apart from their text, so
	there is no view recycling state to worry about.
	*/
	private static final class DashboardAdapter extends BaseAdapter {

		private final LayoutInflater inflater;
		private final List<Tile> tiles;

		DashboardAdapter(Context context, List<Tile> tiles) {
			this.inflater = LayoutInflater.from(context);
			this.tiles = tiles;
		}

		@Override
		public int getCount() {
			return tiles.size();
		}

		@Override
		public Tile getItem(int position) {
			return tiles.get(position);
		}

		@Override
		public long getItemId(int position) {
			return position;
		}

		@Override
		public View getView(int position, View convertView, ViewGroup parent) {
			// convertView is the cell root, not the label - the LinearLayout carries the tile
			// background and padding, so look the TextView up inside it.
			View cell = convertView;
			if (cell == null) {
				cell = inflater.inflate(R.layout.item_dashboard_tile, parent, false);
			}
			TextView label = (TextView) cell.findViewById(R.id.tile_label);
			label.setText(tiles.get(position).label);
			return cell;
		}
	}


	/*
	Emits LOGOUT, drops the local session and returns to the login screen.
	*/
	protected void logout() {
		RaspEvent.ok(RaspEvent.LOGOUT, "PostLogin", uname, RaspEvent.newOpId(), "button=logout");
		BankSession.clear(this);
		Intent i = new Intent(getBaseContext(), LoginActivity.class);
		i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
		startActivity(i);
		finish();
	}

	private void checkEmulatorStatus() {
		Boolean isEmulator = checkIfDeviceIsEmulator();
		if(isEmulator==true)
		{
			Toasteroid.show(this, "Application running on Emulator", Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_LONG);
		}
		else
		{
			Toasteroid.show(this, "Application running on Real device", Toasteroid.STYLES.SUCCESS, Toasteroid.LENGTH_LONG);
		}
	}

	private Boolean checkIfDeviceIsEmulator() {
		if(Build.FINGERPRINT.startsWith("generic")
				|| Build.FINGERPRINT.startsWith("unknown")
				|| Build.MODEL.contains("google_sdk")
				|| Build.MODEL.contains("Emulator")
				|| Build.MODEL.contains("Android SDK built for x86")
				|| Build.MANUFACTURER.contains("Genymotion")
				|| (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
				|| "google_sdk".equals(Build.PRODUCT))
		{
			return true;
		}
		return false;
	}


	void showRootStatus() {
        boolean isrooted = doesSuperuserApkExist("/system/app/Superuser.apk")||
                doesSUexist();
        if(isrooted==true)
        {
            root_status.setText("Rooted Device!!");
        }
        else
        {
            root_status.setText("Device not Rooted!!");
        }
    }

    private boolean doesSUexist() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[] { "/system/bin/which", "su" });
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            if (in.readLine() != null) return true;
            return false;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }

    }

    private boolean doesSuperuserApkExist(String s) {

        File rootFile = new File("/system/app/Superuser.apk");
        Boolean doesexist = rootFile.exists();
        if(doesexist == true)
        {
            return(true);
        }
        else
        {
            return(false);
        }
    }

    // Added for handling menu operations
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	// Added for handling menu operations
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar wil
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			callPreferences();
			return true;
		} else if (id == R.id.action_exit) {
			logout();
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	public void callPreferences() {
		// TODO Auto-generated method stub
		Intent i = new Intent(this, FilePrefActivity.class);
		startActivity(i);
	}
}