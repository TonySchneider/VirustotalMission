package Graphics;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.SwingWorker;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import Backend.MySQLconnection;
import Backend.mainWork;


public class MainPanel extends JPanel implements ActionListener{
	private static final long serialVersionUID = 1L;
	private static final JPanel topPanel = new JPanel(),powerPanel = new JPanel(),logPanel = new JPanel(),buttomPanel = new JPanel();
	private static final JTextPane logs = new JTextPane();
	private final button power = new button("/Images/power.png","/Images/power2.png");
	public MainPanel(){
		setBackground(Color.white);
		setLayout(new GridLayout(2,1));
		
		GridBagConstraints t = new GridBagConstraints();
		
		topPanel.setLayout(new GridBagLayout());
		topPanel.setOpaque(false);
		powerPanel.setOpaque(false);
		logPanel.setOpaque(false);
		power.addActionListener(this);
		
		powerPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridx = 1;
		powerPanel.add(power,c);
		
		t.gridx = 0;
		t.weightx = 0.3;
		topPanel.add(powerPanel,t);
		
		logPanel.setBorder(BorderFactory.createTitledBorder(null, "Logs", TitledBorder.LEFT, TitledBorder.TOP, new Font("Monospace",Font.BOLD,12), Color.RED));
		logs.setPreferredSize(new Dimension(450,190));
//		logs.setLineWrap(true);
		logs.setEditable(false);
		DefaultCaret caret = (DefaultCaret) logs.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		JScrollPane logsScroll = new JScrollPane(logs);
		logPanel.add(logsScroll);
		
		t.weightx = 0.7;
		t.gridx = 1;
		topPanel.add(logPanel,t);
		
		add(topPanel);
		
		buttomPanel.setBorder(BorderFactory.createTitledBorder(null, "malicious IPs", TitledBorder.LEFT, TitledBorder.TOP, new Font("Monospace",Font.BOLD,12), Color.RED));
		JTable table = new JTable();
		
		MySQLconnection.createTableModel();
		
		table.setModel(MySQLconnection.getTableModel());
		table.setFillsViewportHeight(true);
		JScrollPane scrollPane = new JScrollPane(table);
		DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
		centerRenderer.setHorizontalAlignment( JLabel.CENTER );
		for (int i=0;i<4;i++) table.getColumnModel().getColumn(i).setCellRenderer( centerRenderer );
		add(scrollPane);
	}
	@Override
	public void actionPerformed(ActionEvent e) {
		if(e.getSource() == power){
			power.setEnabled(false);
			SwingWorker<Boolean , Integer> sw = new SwingWorker<Boolean, Integer>()  {
				@Override
				protected Boolean doInBackground(){
					mainWork.Do();
					return true;
				} 
				@Override
				protected void done(){
					power.setEnabled(true);
				}
	        };
	        sw.execute();
		}
	}
	public static void refreshTable(){
		
	}
	public static void refreshButtomPanel(){
		buttomPanel.revalidate();
	}

	public synchronized static void setLog(String log,String type){
		StyledDocument doc = logs.getStyledDocument();

        Style style = logs.addStyle("I'm a Style", null);
		if(type.equals("red")){
			StyleConstants.setForeground(style, Color.red);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}else if(type.equals("regular")){
			StyleConstants.setForeground(style, Color.black);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}else if(type.equals("good")){
			StyleConstants.setForeground(style, Color.GREEN);
			try { doc.insertString(doc.getLength(), log+"\n",style); }
	        catch (BadLocationException e){}
		}
	}
}
