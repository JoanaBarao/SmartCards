

import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.util.concurrent.CancellationException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class SwingPasswordCallbackHandler implements CallbackHandler {

	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof PasswordCallback) {
				handlePasswordCallback((PasswordCallback) callbacks[i]);
			} else {
				throw new UnsupportedCallbackException(callbacks[i],
						"Callback not supported " + callbacks[i].getClass().getName());
			}
		}
	}
	
	private void handlePasswordCallback(PasswordCallback passCb) throws UnsupportedCallbackException {
		// dialog
		JPanel panel = new JPanel();
		panel.setLayout(new GridLayout(2, 1));
		
		// label
		panel.add(new JLabel(passCb.getPrompt()));

		// passwort input
		final JTextField txtPwd = new JPasswordField(20);
		panel.add(txtPwd);

		final JOptionPane pane = new JOptionPane(
				panel,
				JOptionPane.QUESTION_MESSAGE,
				JOptionPane.OK_CANCEL_OPTION);
		
		JDialog dialog = pane.createDialog(null, "Login / PIN");

		// set focus to password field
		dialog.addWindowListener(new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				txtPwd.requestFocusInWindow();
			}
		});
		
		// show dialog
		dialog.setVisible(true);
		dialog.dispose();
		int retVal = pane.getValue() != null ? ((Integer) pane.getValue()).intValue() : JOptionPane.CANCEL_OPTION;
		
		switch (retVal) {
		case JOptionPane.OK_OPTION:
			// return password
			passCb.setPassword(txtPwd.getText().toCharArray());
			break;
		default:
			// canceled by user
			throw new CancellationException("Password Callback canceled by user");
		}
	}

}
