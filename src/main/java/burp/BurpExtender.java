package burp;

import org.zenis.BurpScaffold.*;
import org.zenis.BurpScaffold.Entity.Record;
import org.zenis.BurpScaffold.Service.DatabaseService;
import org.zenis.BurpScaffold.Service.RecordService;
import org.zenis.BurpScaffold.Service.TableService;
import org.zenis.BurpScaffold.Utils.IOUtils;

import java.awt.*;
import java.io.*;
import java.sql.SQLException;
import java.util.*;
import javax.swing.*;

public class BurpExtender extends JPanel implements IBurpExtender, ITab,
		IExtensionStateListener, IHttpListener, IContextMenuFactory, IMessageEditorController {

	private static final String  progName="BurpScaffold";
	private static final String  author="zenis <sy5323@126.com>";
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private UIComponent uicomponent;
	private RecordService rcdSVC = new RecordService(this);
	private DatabaseService dbSVC = new DatabaseService();
	private TableService tblSVC = new TableService(this);

	private PrintWriter stdout;
	private OutputStream stderr;
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Burp Scaffold");
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerExtensionStateListener(this);
		this.helpers = callbacks.getHelpers();
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = callbacks.getStderr();

		this.stdout.println("Welcome to use BurpScaffold!");

		uicomponent = new UIComponent(this, callbacks, stdout, stderr);
		uicomponent.registerGetSiteMap();
		uicomponent.registerBcontrols();

		setLayout(new BorderLayout());
		add(uicomponent.getParentJpanel(), BorderLayout.NORTH);
		add(uicomponent.getSplitPane(), BorderLayout.CENTER);

	}

	@Override public String  getTabCaption() { return  progName; }

	@Override public Component getUiComponent() { return this; }

	@Override public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){}

	@Override
	public void extensionUnloaded() {
		try {
			dbSVC.DisconnectDB();
			tblSVC.cleanTable(rcdSVC);
		} catch (Exception e) {
			IOUtils.reportError(BurpExtender.this, stderr, e, "Couldn't close database");
		}
	}

	@Override
	public java.util.List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Import into " + progName);
		i.setEnabled(true);
		i.addActionListener(event -> {
			try {
				for (IHttpRequestResponse message : messages) {
					rcdSVC.insertRequestResponse(message, helpers);
				}
			} catch (SQLException e) {
				IOUtils.reportError(this, stderr, e, "Couldn't import selected messages");
			}
		});
		return Collections.singletonList(i);
	}

	public BurpExtender(){
		// TODO add UI to add/remove columns
	};

	private static final byte[] EMPTY_BYTE_ARRAY = {};

	@Override
	public IHttpService getHttpService() {
		Record rcd = rcdSVC.getRcdByID(tblSVC.getSelectedId());
		if (rcd == null) return null;
		return new IHttpService() {
			public String  getHost() { return rcd.getHost(); }
			public int getPort() { return rcd.getPort(); }
			public String  getProtocol() { return rcd.getProtocol(); }
		};
	}

	@Override
	public byte[] getRequest() {
		Record rcd = rcdSVC.getRcdByID(tblSVC.getSelectedId());
		if (rcd == null) return EMPTY_BYTE_ARRAY;
		return rcd.getRequest().getBytes();
	}

	@Override
	public byte[] getResponse() {
		Record rcd = rcdSVC.getRcdByID(tblSVC.getSelectedId());
		if (rcd == null) return EMPTY_BYTE_ARRAY;
		return rcd.getResponse().getBytes();
	}

	public PrintWriter getStdout() {
		return stdout;
	}

	public OutputStream getStderr() {
		return stderr;
	}

	public TableService getTblSVC() {
		return tblSVC;
	}

	public RecordService getRcdSVC() {
		return rcdSVC;
	}

	public DatabaseService getDbSVC() {
		return dbSVC;
	}

	public IExtensionHelpers getHelpers() {
		return helpers;
	}
}

